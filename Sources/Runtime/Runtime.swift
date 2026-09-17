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

        /// Custom HTTP headers set on every request made by HTTP-based
        /// bundle loaders, including the discovery bundle loader.
        ///
        /// Note: These headers are merged *over* the per-service headers
        /// from the OPA config's `services.<name>.headers`, so an injected
        /// header wins on conflicts. Credential handlers, `ETag` caching,
        /// and long-polling headers are applied afterwards and will
        /// overwrite any conflicting values.
        public let headers: [String: String]?

        /// Where HTTP-based bundle/discovery loader get their
        /// `HTTPClient.Configuration`. Forwarded verbatim.
        public let httpClientConfig: HTTPClientConfigSource?

        /// Cache of long-lived `HTTPClient`s shared by all HTTP-based bundle
        /// loaders (including the discovery loader), so TCP/TLS connections
        /// stay warm across polls. Internal: consumers control it through
        /// ``evictCachedHTTPClient(forService:)`` / ``evictAllCachedHTTPClients()``.
        /// Shut down when `run()` returns.
        let httpClientCache: OPA.HTTPClientCache

        /// Bundle loader type list to use for loading bundles. Ordered by priority.
        private let bundleLoaders: [BundleLoader.Type]

        /// Factory that selects and constructs bundle loaders from the configured
        /// loader-type list and the injected HTTP inputs.
        private let loaderFactory: OPA.BundleLoaderFactory

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
            /// The source of truth for active bundle state.
            var bundleStore = OPA.BundleStore()

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

        /// Snapshot of the currently-active (enforced) bundles.
        public var bundles: [String: OPA.Bundle] {
            state.withLock { $0.bundleStore.bundles }
        }

        /// Snapshot of every configured bundle's status paired with its live
        /// bundle payload.
        public func activeBundles() -> [String: OPA.BundleStatus] {
            state.withLock { $0.bundleStore.activeBundles() }
        }

        /// Cheaper metadata-only snapshot (no bundle payloads copied), modeled on
        /// OPA's Status API `"bundles"` section.
        public func activeBundleMetadata() -> [String: OPA.BundleStatusMetadata] {
            state.withLock { $0.bundleStore.activeBundleMetadata() }
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
        ///   - headers: Custom HTTP headers to set on every request made by
        ///     HTTP-based bundle loaders, including the discovery bundle loader.
        ///   - httpClientConfig: Where bundle loaders get their HTTP client configuration.
        ///   - bundleLoaders: BundleLoader types to use, in priority order.
        ///   - configProvider: An optional config provider. If nil and `config.discovery`
        ///     is set, a ``DiscoveryConfigProvider`` is created automatically.
        ///   - customBuiltins: A dictionary of custom `Rego.BuiltinImpl` implementations
        ///     to use with the `OPA.Engine` at query preparation time.
        public init(
            config: OPA.Config,
            queries: [String]? = nil,
            instanceID: String = UUID().uuidString,
            headers: [String: String]? = nil,
            httpClientConfig: HTTPClientConfigSource? = nil,
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
            self.headers = headers
            self.httpClientConfig = httpClientConfig
            self.bundleLoaders = bundleLoaders
            self.logger = logger ?? Logger(label: "swift-opa.runtime:\(instanceID)")
            self.httpClientCache = OPA.HTTPClientCache(
                logger: self.logger)
            self.loaderFactory = OPA.BundleLoaderFactory(
                loaderTypes: bundleLoaders,
                headers: headers,
                httpClientConfig: self.httpClientConfig,
                httpClientCache: self.httpClientCache,
                logger: self.logger)

            // Build config provider.
            let resolvedProvider: (any OPA.ConfigProvider)?
            if let configProvider {
                self.logger.debug("Using injected config provider.")
                resolvedProvider = configProvider
            } else if config.discovery != nil {
                self.logger.debug("Boot config has a discovery section. Building DiscoveryConfigProvider.")
                do {
                    resolvedProvider = try DiscoveryConfigProvider(
                        bootConfig: config,
                        bundleLoaders: bundleLoaders,
                        headers: headers,
                        httpClientConfig: self.httpClientConfig,
                        httpClientCache: self.httpClientCache,
                        logger: self.logger)
                } catch {
                    self.logger.error("Failed to construct DiscoveryConfigProvider from boot config: \(error)")
                    throw error
                }
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

            // Snapshot the active bundle set + generation consistently.
            let bundles = state.bundleStore.bundles
            let bundleGen = state.bundleStore.generation

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
            guard state.bundleStore.generation == state.preparedBundleGeneration,
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
        // Shut down cached HTTP clients on every exit path (normal return,
        // thrown error, or cancellation). `defer` cannot await, so we bracket
        // the worker group explicitly.
        do {
            try await self.runWorkerGroup()
        } catch {
            await self.httpClientCache.shutdownAll()
            throw error
        }
        await self.httpClientCache.shutdownAll()
    }

    /// Runs the config-provider polling task and the bundle-worker managing
    /// task as a group, blocking until the enclosing task is cancelled.
    private func runWorkerGroup() async throws {
        let provider = state.withLock { $0.configProvider }
        let initialConfig = self.bootConfig

        try await withThrowingTaskGroup(of: Void.self) { group in
            let (configStream, configContinuation) = AsyncStream<OPA.Config>.makeStream()

            // Route each config update from the provider into Runtime state,
            // forwarding the config to the bundle manager only when it actually
            // changed. Only successful, changed configs reach the stream.
            let configSink: OPA.ConfigUpdateSink = { update in
                switch update {
                case .updated(let config):
                    if self.updateConfig(result: .success(config)) {
                        configContinuation.yield(config)
                    }
                case .failed(let error):
                    self.logger.error("Config provider load() failed: \(error)")
                    _ = self.updateConfig(result: .failure(error))
                }
            }

            // Emit the initial config first so it is unambiguously the bundle
            // manager's first input, before any config the provider may produce.
            configContinuation.yield(initialConfig)

            // Start the config provider (e.g., discovery) if present. The
            // provider owns its own polling state machine via run(into:).
            if var provider {
                self.logger.info("Starting config provider.")
                group.addTask {
                    await provider.run(into: configSink)
                    configContinuation.finish()
                    self.logger.info("Stopping config provider.")
                }
            } else {
                // No more configs coming — finish the stream so the bundle
                // manager settles into steady state after the initial config.
                configContinuation.finish()
            }

            // Bundle manager: reconciles bundle loaders against each config,
            // starting/stopping only the delta so persistent loaders keep their
            // ETag + last-known-good bundle across config changes.
            let bundleSink: OPA.BundleUpdateSink = { name, update in
                self.applyBundleUpdate(name: name, update: update)
            }
            let manager = OPA.BundleManager(
                factory: self.loaderFactory,
                httpClientCache: self.httpClientCache,
                sink: bundleSink,
                onRemoved: { names in self.pruneBundles(names) },
                logger: self.logger)
            group.addTask {
                await manager.run(configs: configStream)
            }

            // Block until all workers finish (cancellation or error).
            // If a worker throws, the group cancels the siblings.
            for try await _ in group {}
        }
    }
}

// MARK: - Config Loading

extension OPA.Runtime {
    /// Updates the active config under the config lock and tracks the
    /// state of the last config polling attempt.
    ///
    /// Called from the config provider driver after an off-lock fetch
    /// completes. The critical section is short — only dictionary/enum
    /// comparisons and a small struct write.
    ///
    /// - Returns: `true` when the config generation advanced (a new, changed
    ///   config was applied), so the caller knows to forward it to consumers.
    @discardableResult
    private func updateConfig(
        result: Result<OPA.Config, any Swift.Error>
    ) -> Bool {
        state.withLock { state -> Bool in
            // Deduplicate — skip if the result hasn't meaningfully changed.
            switch (state.latestConfig, result) {
            case (.success(let old), .success(let new))
            where old == new:
                self.logger.debug("Config not modified.")
                return false
            case (.failure(let old), .failure(let new))
            where String(describing: old) == String(describing: new):
                self.logger.debug("Config still failed to load with error: \(new).")
                return false
            case (_, .success(let new)):
                self.logger.debug("Config updated.")
                state.activeConfig = new
                state.configGeneration &+= 1
                state.latestConfig = result
                return true
            default:
                // A new (first or changed) failure. The polling loop already
                // logs load failures at `.error`, so keep this at `.debug`.
                self.logger.debug("Config load failed with a new error.")
                state.latestConfig = result
                return false
            }
        }
    }
}

// MARK: - Bundle Loading

extension OPA.Runtime {
    /// Builds a single bundle loader for `name`, using the same selection policy
    /// as the ``BundleLoaderFactory`` built at init but honoring the caller's
    /// `logger`. Retained for existing callers/tests that inspect a constructed
    /// loader.
    ///
    /// Reads only immutable Runtime state, so it is safe to call from
    /// any thread without locking.
    func getBundleLoader(
        name: String,
        config: OPA.Config,
        logger: Logger
    ) throws -> OPA.BundleLoader {
        let factory = OPA.BundleLoaderFactory(
            loaderTypes: self.bundleLoaders,
            headers: self.headers,
            httpClientConfig: self.httpClientConfig,
            httpClientCache: self.httpClientCache,
            logger: logger)
        return try factory.makeLoader(name: name, config: config)
    }

    /// Applies a single bundle poll outcome to the bundle store.
    ///
    /// Called from bundle polling loops after an off-lock fetch completes.
    private func applyBundleUpdate(name: String, update: OPA.BundleUpdate) {
        let now = Date()
        let activated = state.withLock { state in
            state.bundleStore.update(name: name, update, now: now)
        }
        switch update {
        case .downloaded:
            self.logger.debug(
                activated ? "Activated new bundle \(name)." : "Bundle \(name) re-downloaded, unchanged.")
        case .notModified:
            self.logger.debug("Bundle \(name) not modified.")
        case .failed(let error):
            self.logger.debug(
                "Bundle \(name) poll failed: \(error). Keeping last-known-good bundle, if any.")
        }
    }

    /// Removes the named bundles from the store when a bundle entry is dropped
    /// from the config, so its last-known state does not linger. Bumps the store
    /// generation only when a live entry was actually removed.
    private func pruneBundles(_ names: Set<String>) {
        let removed = state.withLock { state in
            state.bundleStore.remove(names)
        }
        if removed {
            self.logger.debug(
                "Pruned removed bundle(s): \(names.sorted().joined(separator: ", ")).")
        }
    }
}

public typealias DecisionIDGenerator = @Sendable () async throws -> String

// MARK: - HTTP client cache control

extension OPA.Runtime {
    /// Evicts the cached HTTP client for `service`, forcing the next poll to
    /// build a fresh one. Useful when a credential or certificate has rotated
    /// out of band in a way the SDK cannot observe (e.g. an in-memory cert
    /// supplied through a closure-based ``OPA/HTTPClientConfigSource``).
    public func evictCachedHTTPClient(forService service: String) {
        self.httpClientCache.evict(services: [service])
    }

    /// Evicts every cached HTTP client, forcing subsequent polls to rebuild.
    public func evictAllCachedHTTPClients() {
        self.httpClientCache.evictAll()
    }
}

// MARK: - OPA.Runtime convenience initializers

extension OPA.Runtime {
    /// Initializes a Runtime with separate async-only and synchronous builtin dictionaries,
    /// mirroring the typed parameter style used by ``OPA/Engine``.
    ///
    /// Prefer the ``init(config:queries:instanceID:headers:httpClientConfig:bundleLoaders:configProvider:customBuiltins:logger:)``
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
        headers: [String: String]? = nil,
        httpClientConfig: OPA.HTTPClientConfigSource? = nil,
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
            headers: headers,
            httpClientConfig: httpClientConfig,
            bundleLoaders: bundleLoaders,
            configProvider: configProvider,
            customBuiltins: combined,
            logger: logger)
    }
}
