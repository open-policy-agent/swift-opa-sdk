import AsyncHTTPClient
import Logging
import NIOCore  // EventLoopGroup, TimeAmount
import NIOSSL  // TLSConfiguration
import Rego
import Synchronization  // Mutex

extension OPA {
    /// A cache of long-lived ``HTTPClient`` instances, one per service, so
    /// that bundle loaders can benefit from connection pooling done by the clients.
    ///
    /// ## Design
    ///
    /// The ``HTTPClientCache`` manages the life cycle of ``HTTPClient``
    /// instances, and ensures that bundle loaders are not setting up and tearing
    /// down clients constantly. Each ``HTTPClient`` manages its own connection
    /// pool, so under normal operation bundle fetches from the same service
    /// should use connections from that pool rather than opening new connections.
    ///
    /// A fundamental limitation of the the AsyncHTTPClient library is that
    /// different TLS configs require different ``HTTPClient`` instances. This
    /// does put an upper limit on how much connection pooling and reuse is
    /// possible, but there is still substantial benefit for ``Runtime``
    /// instances in normal usage.
    ///
    /// ## Cache identity
    ///
    /// Entries are keyed by service name, and validated on every lookup
    /// against the resolved `HTTPClient.Configuration`. When the resolved
    /// configuration changes (e.g. a rotated client certificate), the stale
    /// client is evicted and a new one built. Comparison of configs is
    /// conservative, so a changed config never incorrectly reuses a client.
    ///
    /// ## Concurrency
    ///
    /// State is guarded by a single `Mutex`. All mutations (lookup, compare,
    /// insert, evict) are synchronous under the lock. The only async work,
    /// `HTTPClient.shutdown()`, always runs *after* the lock is released,
    /// so the lock is never held across an `await`.
    public final class HTTPClientCache: Sendable {
        private struct Entry {
            let client: HTTPClient
            let configuration: HTTPClient.Configuration
        }

        private let entries = Mutex<[String: Entry]>([:])
        private let eventLoopGroup: any EventLoopGroup
        private let logger: Logger

        /// Uses the process-wide singleton `EventLoopGroup`.
        convenience init(logger: Logger? = nil) {
            self.init(eventLoopGroup: .singletonMultiThreadedEventLoopGroup, logger: logger)
        }

        init(eventLoopGroup: any EventLoopGroup, logger: Logger? = nil) {
            self.eventLoopGroup = eventLoopGroup
            self.logger = logger ?? Logger(label: "swift-opa.http-client-cache")
        }

        deinit {
            // Safety net: if the cache is torn down without an explicit
            // `shutdownAll()` (e.g. a loader built for a one-off `load()`
            // outside a running `Runtime`), shut down any remaining clients so
            // they don't trip `HTTPClient`'s "not shut down before deinit"
            // error. The detached task retains the clients until their
            // shutdown completes.
            let remaining: [HTTPClient] = entries.withLock { entries in
                let all = entries.values.map(\.client)
                entries.removeAll()
                return all
            }
            guard !remaining.isEmpty else { return }
            Task {
                for client in remaining {
                    try? await client.shutdown()
                }
            }
        }

        // MARK: - Client usage

        /// Runs `body` with an `HTTPClient` appropriate for `service` and
        /// `configuration`.
        ///
        /// When `cache` is non-nil the client is drawn from (or added to) the
        /// cache and is *not* shut down afterwards. When `cache` is nil (a
        /// loader constructed without a `Runtime` to own client lifecycle),
        /// an ephemeral client is created and shut down around `body`, exactly
        /// as the SDK behaved before client caching existed.
        public static func withClient<T>(
            cache: OPA.HTTPClientCache?,
            service: String,
            configuration: HTTPClient.Configuration,
            backgroundActivityLogger: Logger? = nil,
            isolation: isolated (any Actor)? = #isolation,
            _ body: (HTTPClient) async throws -> sending T
        ) async throws -> T {
            if let cache {
                let client = cache.client(service: service, configuration: configuration)
                return try await body(client)
            }
            return try await HTTPClient.withHTTPClient(
                eventLoopGroup: .singletonMultiThreadedEventLoopGroup,
                configuration: configuration,
                backgroundActivityLogger: backgroundActivityLogger,
                body
            )
        }

        /// Returns the cached client for `service`, rebuilding it when the
        /// resolved configuration has changed since the last call. Any
        /// superseded client is shut down on a detached task. Note that
        /// `HTTPClient.shutdown()` closes the client's connections rather than
        /// draining them, so a request in flight on the superseded client is
        /// interrupted.
        func client(service: String, configuration: HTTPClient.Configuration) -> HTTPClient {
            let (client, stale): (HTTPClient, HTTPClient?) = entries.withLock { entries in
                if let existing = entries[service],
                    Self.configsEquivalentForPooling(existing.configuration, configuration)
                {
                    return (existing.client, nil)
                }
                let stale = entries[service]?.client
                let fresh = HTTPClient(eventLoopGroup: self.eventLoopGroup, configuration: configuration)
                entries[service] = Entry(client: fresh, configuration: configuration)
                return (fresh, stale)
            }
            if let stale {
                self.shutdownDetached(stale)
            }
            return client
        }

        // MARK: - Eviction

        /// Evicts and shuts down the cached clients for the given services.
        /// Used when a config generation change drops services from the config.
        func evict(services: some Sequence<String>) {
            let stale: [HTTPClient] = entries.withLock { entries in
                var removed: [HTTPClient] = []
                for service in services {
                    if let entry = entries.removeValue(forKey: service) {
                        removed.append(entry.client)
                    }
                }
                return removed
            }
            for client in stale {
                self.shutdownDetached(client)
            }
        }

        /// Evicts and shuts down every cached client whose service is not in
        /// `services`. Called when a new config generation is applied, so that
        /// clients for services that are no longer referenced are released
        /// promptly rather than lingering until teardown.
        func retainOnly(services: Set<String>) {
            let stale: [HTTPClient] = entries.withLock { entries in
                let removedKeys = entries.keys.filter { !services.contains($0) }
                var removed: [HTTPClient] = []
                for key in removedKeys {
                    if let entry = entries.removeValue(forKey: key) {
                        removed.append(entry.client)
                    }
                }
                return removed
            }
            for client in stale {
                self.shutdownDetached(client)
            }
        }

        /// Evicts and shuts down every cached client, leaving the cache usable
        /// (a subsequent lookup builds fresh clients). Unlike ``shutdownAll()``
        /// this does not await the shutdowns, so it is safe to call while the
        /// `Runtime` keeps running. Any request in flight on an evicted client
        /// is interrupted.
        func evictAll() {
            let stale: [HTTPClient] = entries.withLock { entries in
                let all = entries.values.map(\.client)
                entries.removeAll()
                return all
            }
            for client in stale {
                self.shutdownDetached(client)
            }
        }

        /// Evicts and shuts down every cached client, concurrently. Called on
        /// `Runtime` teardown, after all pollers have stopped using their
        /// clients, so shutdown latency is bounded by the slowest single client.
        func shutdownAll() async {
            let clients: [HTTPClient] = entries.withLock { entries in
                let all = entries.values.map(\.client)
                entries.removeAll()
                return all
            }
            let logger = self.logger
            await withTaskGroup(of: Void.self) { group in
                for client in clients {
                    group.addTask {
                        do {
                            try await client.shutdown()
                        } catch {
                            logger.debug("HTTPClient shutdown error during shutdownAll: \(error)")
                        }
                    }
                }
            }
        }

        private func shutdownDetached(_ client: HTTPClient) {
            let logger = self.logger
            Task {
                do {
                    try await client.shutdown()
                } catch {
                    logger.debug("HTTPClient shutdown error during eviction: \(error)")
                }
            }
        }

        // MARK: - Configuration equivalence

        /// Conservative equivalence check for pooling: reports `true` only
        /// when the relevant fields for connection identity all match, so a
        /// changed configuration never reuses a stale client (it may only
        /// cause an unnecessary rebuild).
        ///
        /// TLS is compared via `TLSConfiguration.bestEffortEquals`, which
        /// ensures no false-positives. We also compare the publicly-comparable
        /// fields that affect connection identity or behavior.
        /// A handful of fields are not publicly comparable or are
        /// observability hooks (`tracer`, the debug initializers). A caller
        /// who varies only those fields out-of-band can force a rebuild via
        /// the `Runtime`'s manual eviction API.
        static func configsEquivalentForPooling(
            _ a: HTTPClient.Configuration,
            _ b: HTTPClient.Configuration
        ) -> Bool {
            guard Self.tlsConfigsEqual(a.tlsConfiguration, b.tlsConfiguration) else {
                return false
            }
            return a.timeout.connect == b.timeout.connect
                && a.timeout.read == b.timeout.read
                && a.timeout.write == b.timeout.write
                && a.connectionPool == b.connectionPool
                && a.proxy == b.proxy
                && a.httpVersion == b.httpVersion
                && a.dnsOverride == b.dnsOverride
                && a.maximumUsesPerConnection == b.maximumUsesPerConnection
                && a.enableMultipath == b.enableMultipath
                && a.localAddress == b.localAddress
        }

        private static func tlsConfigsEqual(_ a: TLSConfiguration?, _ b: TLSConfiguration?) -> Bool {
            switch (a, b) {
            case (nil, nil):
                return true
            case (let lhs?, let rhs?):
                return lhs.bestEffortEquals(rhs)
            default:
                return false
            }
        }
    }
}
