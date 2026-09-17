import Config
import Logging
import Rego
import Synchronization

extension OPA {
    /// Manages a set of self-driving bundle loaders, reconciling them against a
    /// stream of configurations.
    ///
    /// On each new config, only the delta is applied: loaders for unchanged
    /// bundle entries keep running untouched (so their ETag and last-known-good
    /// bundle survive), loaders for removed entries are stopped, and loaders for
    /// added or changed entries are (re)started. Each loader owns its own polling
    /// loop via ``BundleLoader/run(name:into:)``.
    ///
    /// ``BundleManager`` is Runtime-independent: it reports bundle updates through
    /// an injected ``BundleUpdateSink`` and prunes removed entries through an
    /// injected callback, so callers can build their own bundle management on top
    /// of the SDK's loaders. Drive it with ``run(configs:)`` from a single task.
    ///
    /// ## Concurrency
    ///
    /// The running-loader table is guarded by a `Mutex`. Task cancellation and
    /// awaiting always happen off-lock, so the lock is never held across an
    /// `await`. ``run(configs:)`` applies configs serially, so no two ``apply``
    /// calls overlap.
    public final class BundleManager: Sendable {
        /// Identity of a bundle entry for delta detection. Two entries with equal
        /// fingerprints resolve to the same loader configuration, so the running
        /// loader can be kept as-is.
        struct Fingerprint: Equatable, Sendable {
            let bundle: OPA.BundleSourceConfig
            let service: OPA.ServiceConfig?
        }

        private struct Running {
            let task: Task<Void, Never>
            let fingerprint: Fingerprint
        }

        private let factory: OPA.BundleLoaderFactory
        private let httpClientCache: OPA.HTTPClientCache?
        private let sink: OPA.BundleUpdateSink
        private let onRemoved: (@Sendable (Set<String>) -> Void)?
        private let logger: Logger
        private let running = Mutex<[String: Running]>([:])
        /// Bundle names present in the last applied config. Tracked so a name
        /// that leaves the config is pruned even if its loader never entered
        /// `running` (e.g. its construction failed).
        private let configuredNames = Mutex<Set<String>>([])

        public init(
            factory: OPA.BundleLoaderFactory,
            httpClientCache: OPA.HTTPClientCache?,
            sink: @escaping OPA.BundleUpdateSink,
            onRemoved: (@Sendable (Set<String>) -> Void)? = nil,
            logger: Logger? = nil
        ) {
            self.factory = factory
            self.httpClientCache = httpClientCache
            self.sink = sink
            self.onRemoved = onRemoved
            self.logger = logger ?? Logger(label: "swift-opa.bundle-manager")
        }

        /// Drives the manager from a config source. Applies each config's delta
        /// serially, then keeps the running loaders alive until the source ends
        /// or the enclosing `Task` is cancelled, then shuts them all down.
        public func run<S: AsyncSequence & Sendable>(configs: S) async where S.Element == OPA.Config {
            do {
                for try await config in configs {
                    await apply(config: config)
                }
            } catch {
                self.logger.debug("Config source ended with error: \(error)")
            }
            // The config source ended (or the stream was cancelled). Keep the
            // running loaders alive until this task is cancelled, then tear
            // everything down. Because the config loop has fully finished here,
            // shutdown() snapshots the complete running set and no late-spawned
            // loader can be orphaned.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(3600))
            }
            await shutdown()
        }

        /// Reconciles the running loaders against `config`, starting/stopping only
        /// the delta. Not safe to call concurrently with itself. ``run(configs:)``
        /// serializes it.
        func apply(config: OPA.Config) async {
            let desired: [String: Fingerprint] = config.bundles.reduce(into: [:]) { acc, entry in
                acc[entry.key] = Fingerprint(
                    bundle: entry.value, service: config.services[entry.value.service])
            }

            // Stop loaders whose entry was removed or changed. Cancel and await
            // off-lock so an in-flight request drains before we drop its client.
            let toStop: [String: Task<Void, Never>] = running.withLock { running in
                var stop: [String: Task<Void, Never>] = [:]
                for (name, r) in running where desired[name] != r.fingerprint {
                    stop[name] = r.task
                }
                return stop
            }
            for (name, task) in toStop {
                self.logger.info("Stopping bundle loader for bundle: \(name).")
                task.cancel()
            }
            for (_, task) in toStop {
                await task.value
            }
            running.withLock { running in
                for name in toStop.keys { running.removeValue(forKey: name) }
            }

            // Prune storage for entries that left the config entirely (not merely
            // changed), so stale status does not linger — including for a bundle
            // whose loader failed to construct and so never entered `running`.
            let removedNames = configuredNames.withLock { previous -> Set<String> in
                let removed = previous.subtracting(desired.keys)
                previous = Set(desired.keys)
                return removed
            }
            if !removedNames.isEmpty, let onRemoved {
                onRemoved(removedNames)
            }

            // Release cached HTTP clients for services this config no longer
            // references. Done after cancellations so a client is never shut
            // down from under a still-unwinding request.
            var referencedServices = Set(config.bundles.values.map(\.service))
            if let discoveryService = config.discovery?.service {
                referencedServices.insert(discoveryService)
            }
            httpClientCache?.retainOnly(services: referencedServices)

            // Start loaders for added or changed entries. Unchanged entries are
            // already running and are left untouched (keeping their ETag +
            // last-known-good bundle). apply() is serialized by run(configs:),
            // so a single snapshot of the running names is sufficient.
            let runningNames = running.withLock { Set($0.keys) }
            for (name, fingerprint) in desired where !runningNames.contains(name) {
                do {
                    var loader = try factory.makeLoader(name: name, config: config)
                    let sink = self.sink
                    self.logger.info("Starting bundle loader for bundle: \(name).")
                    let task = Task { await loader.run(name: name, into: sink) }
                    running.withLock { $0[name] = Running(task: task, fingerprint: fingerprint) }
                } catch {
                    // Setting up the loader failed. Record the error.
                    sink(name, .failed(error))
                }
            }
        }

        /// Cancels and awaits every running loader, clearing the table.
        func shutdown() async {
            let tasks = running.withLock { running -> [Task<Void, Never>] in
                let all = running.values.map(\.task)
                running.removeAll()
                return all
            }
            for task in tasks { task.cancel() }
            for task in tasks { await task.value }
        }
    }
}
