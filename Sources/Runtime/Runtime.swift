import AST
import AsyncHTTPClient
import Config
import Foundation
import Logging
import Rego
import RegoExtensions
import SWCompression
import Synchronization

// TODO: Provide a rough equivalent of hooks.Hooks, once we have appropriate infrastructure to warrant it.
// TODO: Port over the hacky bundle compilation via shell-out-to-OPA approach, and add a CLI flag to force SHA sum check before executing. (Maybe also a compile flag/trait?)

extension OPA {
    /// Runtime represents an instance of a Rego policy engine,
    /// and can be started with several options that control
    /// configuration, logging, and lifecycle.
    ///
    /// It is intended to provide a "policy decision point (PDP)
    /// in a box", and is meant to be embedded into larger Swift
    /// applications. Once configured, the Runtime will
    /// automatically handle applying updates to the underlying
    /// policy and data stores as needed.
    ///
    /// ## Concurrency
    ///
    /// `Runtime` is a `final class` that conforms to `Sendable`. All
    /// internal mutable state lives in a single `State` struct guarded by
    /// one `Mutex<State>`. The lock is never held across an `await`, so
    /// all long-running async work (bundle/config fetches, query
    /// preparation, evaluation) runs lock-free; the lock is taken only
    /// for short, synchronous critical sections that read or publish
    /// snapshots and bump generation counters.
    ///
    /// ## Lifecycle
    ///
    /// After initialization, call ``run()`` to start background workers
    /// (config providers like discovery, bundle polling, etc.). The `run()`
    /// method blocks until the enclosing `Task` is cancelled, at which
    /// point all workers are torn down via structured concurrency.
    ///
    /// ```swift
    /// let runtime = try OPA.Runtime(config: myConfig)
    /// let runtimeTask = Task { try await runtime.run() }
    ///
    /// // Make policy decisions at any time while run() is active:
    /// let result = try await runtime.decision("authz/allow", input: myInput)
    ///
    /// // Shut down when done:
    /// runtimeTask.cancel()
    /// ```
    ///
    /// You can also use the Runtime without calling `run()` — it will
    /// function with whatever bundles were loaded at init time, but
    /// config providers and bundle polling will not be active.
    public final class Runtime: Sendable {
        // MARK: Immutable state

        /// The immutable boot configuration. Retained for merge precedence
        /// when a config provider produces new configuration.
        public let bootConfig: OPA.Config

        /// The ID this Runtime instance uses to identify itself in logs and traces.
        public let instanceID: String

        /// A set of additional builtins that will be provided to the Engine
        /// during query preparation.
        public let customBuiltins: [String: Rego.BuiltinImpl]

        /// HTTP client configuration to use in bundle loaders.
        public let httpClientConfig: HTTPClient.Configuration?

        /// Bundle loader type list to use for loading bundles. Ordered by priority.
        private let bundleLoaders: [BundleLoader.Type]

        public let logger: Logger

        // MARK: Mutable state (guarded by `state`)

        private struct State {
            // --- Configuration ---
            var activeConfig: OPA.Config
            var latestConfig: Result<OPA.Config, any Swift.Error>?
            /// Monotonic counter incremented on every config change.
            var configGeneration: UInt64
            /// Optional config provider (e.g. discovery) that produces
            /// configuration updates over time. Built at init from the boot
            /// config or injected directly as an init parameter.
            var configProvider: (any OPA.ConfigProvider)?

            // --- Bundles ---
            /// Storage for loaded bundles (both successful and failed).
            var bundleStorage: [String: Result<OPA.Bundle, any Swift.Error>] = [:]
            /// Monotonic counter incremented on every bundle change.
            /// Used to detect interleaved updates during async preparation.
            var bundleGeneration: UInt64 = 0
            /// Cache of successful bundles, derived from `bundleStorage`.
            /// Rebuilt lazily when `bundleGeneration` advances past
            /// `cachedBundlesGeneration`.
            var cachedBundles: [String: OPA.Bundle] = [:]
            /// Sentinel `.max` forces the first read to populate the cache.
            var cachedBundlesGeneration: UInt64 = .max

            // --- Queries / Prepared queries ---
            /// Set of "always on" queries that will be automatically prepared
            /// on bundle changes.
            var queries: Set<String>
            /// Cache for prepared queries. Invalidated when bundles change.
            /// FUTURE: Optimization opportunity — invalidate only the
            /// affected *subset* of queries.
            var preparedQueries: [String: OPA.Engine.PreparedQuery] = [:]
            /// Monotonic counter incremented on every query set change.
            var queryGeneration: UInt64
            /// Bundle generation observed at the last successful prepare.
            var preparedBundleGeneration: UInt64 = 0
            /// Query generation observed at the last successful prepare.
            var preparedQueryGeneration: UInt64 = 0
        }
        private let state: Mutex<State>

        // MARK: Public synchronous accessors
        //
        // Each accessor below briefly takes the lock and returns a
        // by-value snapshot.

        /// The active configuration this Runtime is using.
        public var activeConfig: OPA.Config {
            state.withLock { $0.activeConfig }
        }

        /// Result of the last config load attempt.
        public var latestConfig: Result<OPA.Config, any Swift.Error>? {
            state.withLock { $0.latestConfig }
        }

        /// Snapshot of the bundle storage, including failed loads.
        public var bundleStorage: [String: Result<OPA.Bundle, any Swift.Error>] {
            state.withLock { $0.bundleStorage }
        }

        /// Snapshot of successfully-loaded bundles.
        public var bundles: [String: OPA.Bundle] {
            state.withLock { state in
                if state.cachedBundlesGeneration != state.bundleGeneration {
                    var result: [String: OPA.Bundle] = [:]
                    result.reserveCapacity(state.bundleStorage.count)
                    for (name, storage) in state.bundleStorage {
                        if case .success(let bundle) = storage {
                            result[name] = bundle
                        }
                    }
                    state.cachedBundles = result
                    state.cachedBundlesGeneration = state.bundleGeneration
                }
                return state.cachedBundles
            }
        }

        /// Snapshot of the registered query set.
        public var queries: Set<String> {
            state.withLock { $0.queries }
        }

        /// The async-only builtins registered with this Runtime, derived from ``customBuiltins``.
        public var customAsyncBuiltins: [String: Rego.AsyncBuiltin] {
            customBuiltins.compactMapValues {
                guard case .asyncOnly(let f) = $0 else { return nil }
                return f
            }
        }

        /// The synchronous builtins registered with this Runtime, derived from ``customBuiltins``.
        public var customSyncBuiltins: [String: Rego.SyncBuiltin] {
            customBuiltins.compactMapValues {
                guard case .sync(let f) = $0 else { return nil }
                return f
            }
        }

        // MARK: Init

        /// Initialize a Runtime with the given boot configuration.
        ///
        /// If the boot config contains a `discovery` section and no explicit
        /// `configProvider` is supplied, a ``DiscoveryConfigProvider`` is
        /// created automatically.
        ///
        /// Note: No bundle fetching occurs until `run()` is called.
        ///
        /// - Parameters:
        ///   - config: The boot configuration.
        ///   - queries: Initial set of queries to prepare after bundles are loaded.
        ///   - instanceID: An identifier for this Runtime instance.
        ///   - httpClientConfig: The HTTP client configuration to use for bundle loaders.
        ///   - bundleLoaders: BundleLoader types to use, in priority order.
        ///   - configProvider: An optional config provider. If nil and `config.discovery`
        ///     is set, a ``DiscoveryConfigProvider`` is created automatically.
        ///   - customBuiltins: A dictionary of custom `Rego.BuiltinImpl` implementations
        ///     to use with the `OPA.Engine` at query preparation time.
        public init(
            config: OPA.Config,
            queries: [String]? = nil,
            instanceID: String = UUID().uuidString,
            httpClientConfig: HTTPClient.Configuration? = nil,
            bundleLoaders: [BundleLoader.Type] = [
                OPA.DiskBasedBundleLoader.self,
                OPA.RESTClientBundleLoader.self,
            ],
            configProvider: (any OPA.ConfigProvider)? = nil,
            customBuiltins: [String: Rego.BuiltinImpl] = [:],
            logger: Logger? = nil
        ) throws {
            self.bootConfig = config
            self.instanceID = instanceID
            self.customBuiltins = SDKBuiltinFuncs.sdkDefaultBuiltins.merging(
                customBuiltins, uniquingKeysWith: { (_, new) in new })
            self.httpClientConfig = httpClientConfig ?? HTTPClient.Configuration.singletonConfiguration
            self.bundleLoaders = bundleLoaders
            self.logger = logger ?? Logger(label: "swift-opa.runtime:\(instanceID)")

            // Build config provider.
            let resolvedProvider: (any OPA.ConfigProvider)?
            if let configProvider {
                resolvedProvider = configProvider
            } else if config.discovery != nil {
                resolvedProvider = try DiscoveryConfigProvider(bootConfig: config, bundleLoaders: bundleLoaders)
            } else {
                resolvedProvider = nil
            }

            let initialQueries = Set(queries ?? [])
            self.state = Mutex(
                State(
                    activeConfig: config,
                    latestConfig: nil,
                    configGeneration: 0,
                    configProvider: resolvedProvider,
                    queries: initialQueries,
                    queryGeneration: initialQueries.isEmpty ? 0 : 1))
        }
    }
}

// MARK: - Query & Decision

extension OPA.Runtime {
    /// Adds a query that will automatically be prepared for later evaluation.
    public func addQuery(_ query: String) {
        state.withLock { state in
            if state.queries.insert(query).inserted {
                state.queryGeneration &+= 1
            }
        }
    }

    /// Adds a list of queries from a sequence that will automatically be prepared for later evaluation.
    public func addQueries<S>(_ queries: S) where String == S.Element, S: Sequence {
        state.withLock { state in
            if !state.queries.isSuperset(of: queries) {
                state.queries.formUnion(queries)
                state.queryGeneration &+= 1
            }
        }
    }

    /// Removes a query that will automatically be prepared for later evaluation.
    public func removeQuery(_ query: String) {
        state.withLock { state in
            if state.queries.remove(query) != nil {
                state.preparedQueries.removeValue(forKey: query)
                state.queryGeneration &+= 1
            }
        }
    }

    /// Removes a list of queries from the set the Runtime maintains.
    public func removeQueries<S>(_ queries: S) where String == S.Element, S: Sequence {
        state.withLock { state in
            let queryCount = state.queries.count
            state.queries.subtract(queries)
            for query in queries {
                state.preparedQueries.removeValue(forKey: query)
            }
            if state.queries.count < queryCount {
                state.queryGeneration &+= 1
            }
        }
    }

    /// Action computed under the lock describing what `prepare()`
    /// should do off-lock.
    private enum PrepareAction {
        case upToDate
        /// Prepare only the listed queries and merge into existing cache.
        case partial(queriesToPrepare: Set<String>, queryGen: UInt64)
        /// Rebuild the entire prepared-query cache.
        case full(queriesToPrepare: Set<String>, bundleGen: UInt64, queryGen: UInt64)
    }

    /// Prepares queries for later evaluation. Intended for use only
    /// within the Runtime to ensure a set of prepared queries is available.
    ///
    /// Concurrency notes:
    ///  - All long-running work (engine setup, query preparation) runs
    ///    *without* the lock held.
    ///  - Generations are snapshotted before going off-lock so that on
    ///    commit we can detect that newer writes have invalidated our
    ///    work; in that case we still publish prepared queries (they are
    ///    not wrong, just possibly stale) but record the snapshot
    ///    generations so subsequent callers re-prepare.
    private func prepare(adhocQueries: [String]) async throws -> [String: OPA.Engine.PreparedQuery] {
        // Decide what work to do under the lock, and snapshot the bundle
        // set + generations consistently with that decision.
        let bundleSnapshot: [String: OPA.Bundle]
        let action: PrepareAction
        (bundleSnapshot, action) = state.withLock { state -> ([String: OPA.Bundle], PrepareAction) in
            // Ensure any new ad-hoc queries are tracked.
            let adhocSet = Set(adhocQueries)
            if !adhocSet.isSubset(of: state.queries) {
                state.queries.formUnion(adhocSet)
                state.queryGeneration &+= 1
            }

            // Refresh the cached bundle map if it's behind.
            if state.cachedBundlesGeneration != state.bundleGeneration {
                var result: [String: OPA.Bundle] = [:]
                result.reserveCapacity(state.bundleStorage.count)
                for (name, storage) in state.bundleStorage {
                    if case .success(let bundle) = storage {
                        result[name] = bundle
                    }
                }
                state.cachedBundles = result
                state.cachedBundlesGeneration = state.bundleGeneration
            }
            let bundles = state.cachedBundles
            let bundleGen = state.bundleGeneration

            let sameBundleGen = bundleGen == state.preparedBundleGeneration
            let sameQueryGen = state.queryGeneration == state.preparedQueryGeneration
            let action: PrepareAction
            switch (sameBundleGen, sameQueryGen) {
            case (true, true):
                action = .upToDate
            case (true, false):
                let unprepared = state.queries.subtracting(state.preparedQueries.keys)
                if unprepared.isEmpty {
                    action = .upToDate
                } else {
                    action = .partial(queriesToPrepare: unprepared, queryGen: state.queryGeneration)
                }
            default:
                action = .full(
                    queriesToPrepare: state.queries,
                    bundleGen: bundleGen,
                    queryGen: state.queryGeneration)
            }
            return (bundles, action)
        }

        switch action {
        case .upToDate:
            // Nothing to do; return whatever's currently published.
            return state.withLock { $0.preparedQueries }

        case .partial(let queriesToPrepare, let queryGen):
            let pq = try await Self.prepareQueries(
                bundles: bundleSnapshot,
                queries: queriesToPrepare,
                customBuiltins: customBuiltins)
            return state.withLock { state in
                state.preparedQueries.merge(pq, uniquingKeysWith: { (_, new) in new })
                // Only mark "caught up" to the generation we snapshotted.
                if state.preparedQueryGeneration < queryGen {
                    state.preparedQueryGeneration = queryGen
                }
                return state.preparedQueries
            }

        case .full(let queriesToPrepare, let bundleGen, let queryGen):
            let pq = try await Self.prepareQueries(
                bundles: bundleSnapshot,
                queries: queriesToPrepare,
                customBuiltins: customBuiltins)
            return state.withLock { state in
                state.preparedQueries = pq
                // Only mark "caught up" to the generations we snapshotted.
                // If a newer generation arrived mid-prepare, the next
                // caller will see the mismatch and re-prepare.
                if state.preparedBundleGeneration < bundleGen {
                    state.preparedBundleGeneration = bundleGen
                }
                if state.preparedQueryGeneration < queryGen {
                    state.preparedQueryGeneration = queryGen
                }
                return state.preparedQueries
            }
        }
    }

    /// Prepares all queries against the given set of bundles.
    /// Runs without any lock held.
    private static func prepareQueries(
        bundles: [String: OPA.Bundle],
        queries: Set<String>,
        customBuiltins: [String: Rego.BuiltinImpl] = [:]
    ) async throws -> [String: OPA.Engine.PreparedQuery] {
        var engine = OPA.Engine(bundles: bundles, capabilities: nil, customBuiltins: customBuiltins)
        var pq: [String: OPA.Engine.PreparedQuery] = Dictionary(minimumCapacity: queries.count)
        for query in queries {
            pq[query] = try await engine.prepareForEvaluation(query: query)
        }
        return pq
    }

    /// Synchronous fast-path read. Returns nil if the prepared-query
    /// cache is stale relative to the current bundle/query generations.
    private func cachedPreparedQuery(for query: String) -> OPA.Engine.PreparedQuery? {
        return state.withLock { state in
            guard state.bundleGeneration == state.preparedBundleGeneration,
                state.queryGeneration == state.preparedQueryGeneration
            else { return nil }
            return state.preparedQueries[query]
        }
    }

    /// `decision` generates a policy decision from a query, using
    /// a provided input value.
    ///
    /// Note: Once a query has been added with `addQuery`, or by calling
    /// `decision`, it will automatically be prepared and cached as
    /// bundles are updated, unless removed by a call to `removeQuery`.
    public func decision(
        _ query: String,
        input: AST.RegoValue,
        decisionID: String = UUID().uuidString
    ) async throws -> OPA.DecisionResult {
        // Fast path: locks are taken only briefly to read cached state,
        // then the prepared query is evaluated without any lock held.
        if let pq = self.cachedPreparedQuery(for: query) {
            let result = try await pq.evaluate(input: input)
            self.logger.info("decision: \(decisionID), result: \(result)")
            return OPA.DecisionResult(id: decisionID, result: result)
        }

        // Slow path: prepare (off-lock), then evaluate.
        let pqs = try await self.prepare(adhocQueries: [query])
        guard let pq = pqs[query] else {
            self.logger.error(
                "decision: \(decisionID), error: Could not find prepared query for entrypoint \(query)")
            throw RuntimeError(
                code: .bundleUnpreparedError,
                message: "Could not find prepared query for entrypoint \(query)")
        }
        let result = try await pq.evaluate(input: input)
        self.logger.debug("decision: \(decisionID), result: \(result)")
        return OPA.DecisionResult(id: decisionID, result: result)
    }
}

// MARK: - Lifecycle

extension OPA.Runtime {
    /// Starts the Runtime's background workers and blocks until cancelled.
    ///
    /// This creates a task group containing:
    ///  - A **config provider polling task** (if configured) that repeatedly
    ///    calls ``OPA/ConfigProvider/load()`` and emits results to a stream.
    ///  - A **bundle work group managing task** that consumes configs from
    ///    the stream and (re)spawns bundle polling tasks for configured
    ///    bundle resources.
    ///
    /// The initial active config is always emitted to bootstrap bundle
    /// workers, even if no config provider is present.
    public func run() async throws {
        let provider = state.withLock { $0.configProvider }
        let initialConfig = self.bootConfig

        try await withThrowingTaskGroup(of: Void.self) { group in
            let (configStream, configContinuation) = AsyncStream<Result<OPA.Config, Error>>.makeStream()

            // Start the config provider polling loop (e.g., discovery) if present.
            if var provider {
                let polling = Self.pollingConfig(for: provider)
                self.logger.info("Starting config provider.")
                group.addTask {
                    defer { configContinuation.finish() }

                    var currentConfigGeneration = self.state.withLock { $0.configGeneration }
                    while !Task.isCancelled {
                        let result = await provider.load()

                        // Attempt to update the active config. Only publish on change.
                        self.updateConfig(result: result)
                        let newConfigGeneration = self.state.withLock { $0.configGeneration }
                        if currentConfigGeneration != newConfigGeneration {
                            configContinuation.yield(result)
                        }
                        currentConfigGeneration = newConfigGeneration

                        let longPollingEnabled: Bool = {
                            if let httpProvider = provider as? any OPA.HTTPConfigProvider {
                                return httpProvider.isLongPollingEnabled()
                            }
                            return false
                        }()

                        if !longPollingEnabled {
                            let sleepTime = Int64.random(
                                in: (polling?.minDelaySeconds ?? 60)...(polling?.maxDelaySeconds ?? 120)
                            )
                            do {
                                try await Task.sleep(for: .seconds(sleepTime))
                            } catch {
                                break
                            }
                        }
                    }

                    self.logger.info("Stopping config provider.")
                }
            }

            // Emit the initial config to bootstrap bundle workers.
            configContinuation.yield(.success(initialConfig))
            if provider == nil {
                // No more configs coming — finish the stream so the bundle
                // worker task exits after processing the initial config.
                configContinuation.finish()
            }

            // Bundle worker group task: consumes configs, manages bundle loaders.
            group.addTask {
                var currentWorkers: Task<Void, Never>? = nil

                for await latestConfig in configStream {
                    guard case .success(let config) = latestConfig else {
                        // Either we have a valid new config and need to restart
                        // everything, or there was an error, and we should go
                        // back to waiting for a good config to arrive.
                        continue
                    }

                    // Tear down previous generation of pollers.
                    if let currentWorkers {
                        self.logger.info("Stopping previous generation of bundle loaders.")
                        currentWorkers.cancel()
                        await currentWorkers.value
                    }

                    // Spawn new bundle downloaders as a group.
                    // The nested task here allows cancelling the entire
                    // group of bundle loader workers when we encounter
                    // a new config.
                    self.logger.info("Starting new generation of bundle loaders.")
                    currentWorkers = Task { [self] in
                        await withTaskGroup(of: Void.self) { bundleGroup in
                            for name in config.bundles.keys {
                                self.logger.info("Starting bundle loader for bundle: \(name).")
                                bundleGroup.addTask {
                                    do {
                                        var loader = try self.getBundleLoader(
                                            name: name,
                                            config: config,
                                            logger: self.logger)
                                        var longPollingEnabled = false
                                        let polling = config.bundles[name]?.downloaderConfig.polling

                                        while !Task.isCancelled {
                                            // Attempt to fetch bundle. Update storage.
                                            let result = await loader.load()
                                            self.updateBundleResult(name: name, result: result)

                                            // If our loader supports it, check long polling flag.
                                            if let httpLoader = loader as? OPA.HTTPBundleLoader {
                                                longPollingEnabled = httpLoader.isLongPollingEnabled()
                                            }

                                            // Sleep until next polling interval.
                                            // If long-polling, the wait is happening in the loader, so skip this.
                                            if !longPollingEnabled {
                                                do {
                                                    let sleepTime = Int64.random(
                                                        in: (polling?.minDelaySeconds ?? 60)...(polling?.maxDelaySeconds
                                                            ?? 120))
                                                    try await Task.sleep(for: .seconds(sleepTime))
                                                } catch {
                                                    break  // Task was cancelled — exit cleanly.
                                                }
                                            }
                                        }
                                    } catch {
                                        // Something failed around setting up the bundle loader. Record the error.
                                        self.updateBundleResult(name: name, result: .failure(error))
                                    }
                                    self.logger.info("Stopping bundle loader for bundle: \(name).")
                                }
                            }
                            // TaskGroup blocks here until all pollers finish or task is canceled.
                        }
                    }
                }

                // The config stream ended (e.g. no config provider).
                // Keep current bundle pollers alive until this task is
                // cancelled.
                let workersToAwait = currentWorkers
                await withTaskCancellationHandler {
                    await workersToAwait?.value
                } onCancel: {
                    workersToAwait?.cancel()
                }
            }

            // Block until all workers finish (cancellation or error).
            // If a worker throws, the group cancels the siblings.
            for try await _ in group {}
        }
    }

    /// Extracts the polling config from a known provider type.
    /// Currently specializes on ``DiscoveryConfigProvider``; extend as
    /// additional providers are added.
    private static func pollingConfig(
        for provider: any OPA.ConfigProvider
    ) -> OPA.PollingConfig? {
        if let discovery = provider as? OPA.DiscoveryConfigProvider {
            return discovery.pollingConfig()
        }
        return nil
    }
}

// MARK: - Config Loading

extension OPA.Runtime {
    /// Updates the active config under the config lock and tracks the
    /// state of the last config polling attempt.
    ///
    /// Called from the config polling loop after an off-lock fetch
    /// completes. The critical section is short — only dictionary/enum
    /// comparisons and a small struct write.
    private func updateConfig(
        result: Result<OPA.Config, any Swift.Error>
    ) {
        state.withLock { state in
            // Deduplicate — skip if the result hasn't meaningfully changed.
            switch (state.latestConfig, result) {
            case (.success(let old), .success(let new))
            where old == new:
                self.logger.debug("Config not modified.")
                return
            case (.failure(let old), .failure(let new))
            where old.localizedDescription == new.localizedDescription:
                self.logger.debug("Config still failed to load with error: \(new).")
                return
            case (_, .success(let new)):
                state.activeConfig = new
                state.configGeneration &+= 1
            default:
                self.logger.debug("Updating config.")
                break
            }
            state.latestConfig = result
        }
    }
}

// MARK: - Bundle Loading

extension OPA.Runtime {
    /// Builds a single bundle loader from the configured loader-type list,
    /// based on its name and the OPA config.
    ///
    /// Reads only immutable Runtime state, so it is safe to call from
    /// any thread without locking.
    func getBundleLoader(
        name: String,
        config: OPA.Config,
        logger: Logger
    ) throws -> OPA.BundleLoader {
        var bundleLoader: OPA.BundleLoader?
        for loaderType in self.bundleLoaders {
            if loaderType.compatibleWithConfig(config: config, bundleResourceName: name) {
                bundleLoader = try loaderType.init(config: config, bundleResourceName: name, logger: logger)
                break
            }
        }

        guard let loader = bundleLoader else {
            throw RuntimeError(
                code: .internalError,
                message: "Unsupported bundle source for bundle \(name)")
        }

        return loader
    }

    /// Applies a single bundle result to the runtime's bundle state and
    /// bumps the bundle generation counter.
    ///
    /// Called from bundle polling loops after an off-lock fetch completes.
    /// The critical section is short — only synchronous dictionary updates.
    private func updateBundleResult(
        name: String,
        result: Result<OPA.Bundle, any Swift.Error>
    ) {
        state.withLock { state in
            // Deduplicate — skip if the result hasn't meaningfully changed.
            switch (state.bundleStorage[name], result) {
            case (.success(let old), .success(let new))
            where old == new:
                self.logger.debug("Bundle \(name) not modified.")
                return
            case (.failure(let old), .failure(let new))
            where old.localizedDescription == new.localizedDescription:
                self.logger.debug("Bundle \(name) still failed to load with error: \(new).")
                return
            default:
                self.logger.debug("Updating bundle \(name).")
                break
            }
            state.bundleStorage[name] = result
            state.bundleGeneration &+= 1
        }
    }
}

public typealias DecisionIDGenerator = @Sendable () async throws -> String

// MARK: - OPA.Runtime convenience initializers

extension OPA.Runtime {
    /// Initializes a Runtime with separate async-only and synchronous builtin dictionaries,
    /// mirroring the typed parameter style used by ``OPA/Engine``.
    ///
    /// Prefer the ``init(config:queries:instanceID:httpClientConfig:bundleLoaders:configProvider:customBuiltins:logger:)``
    /// overload that accepts ``Rego/BuiltinImpl`` values when possible — it carries sync/async
    /// intent in the type and avoids an extra merge step. Use this overload when you already hold
    /// typed dictionaries and don't want to convert them manually.
    ///
    /// - Parameters:
    ///   - customAsyncBuiltins: Async-only builtins. Available on the async VM path only.
    ///   - customSyncBuiltins: Synchronous builtins. Available on both the async and sync VM paths.
    public convenience init(
        config: OPA.Config,
        queries: [String]? = nil,
        instanceID: String = UUID().uuidString,
        httpClientConfig: HTTPClient.Configuration? = nil,
        bundleLoaders: [OPA.BundleLoader.Type] = [
            OPA.DiskBasedBundleLoader.self,
            OPA.RESTClientBundleLoader.self,
        ],
        configProvider: (any OPA.ConfigProvider)? = nil,
        customAsyncBuiltins: [String: Rego.AsyncBuiltin] = [:],
        customSyncBuiltins: [String: Rego.SyncBuiltin] = [:],
        logger: Logger? = nil
    ) throws {
        var combined: [String: Rego.BuiltinImpl] = Dictionary(
            minimumCapacity: customAsyncBuiltins.count + customSyncBuiltins.count)
        for (name, f) in customAsyncBuiltins { combined[name] = .asyncOnly(f) }
        for (name, f) in customSyncBuiltins { combined[name] = .sync(f) }
        try self.init(
            config: config,
            queries: queries,
            instanceID: instanceID,
            httpClientConfig: httpClientConfig,
            bundleLoaders: bundleLoaders,
            configProvider: configProvider,
            customBuiltins: combined,
            logger: logger)
    }
}
