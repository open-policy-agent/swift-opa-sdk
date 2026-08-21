import AsyncHTTPClient
import NIOCore  // TimeAmount
import NIOSSL  // TLSConfiguration
import Rego  // OPA namespace
import Testing

@testable import Runtime

// MARK: - HTTPClientCache unit tests
//
// These exercise the cache's identity + eviction logic directly, without any
// network I/O (creating an `HTTPClient` does not open a connection).
// The end-to-end connection-reuse assertions live in the server-based reuse tests.

@Suite("HTTPClientCacheTests")
struct HTTPClientCacheTests {

    private func config(connect: TimeAmount) -> HTTPClient.Configuration {
        var c = HTTPClient.Configuration()
        c.timeout = HTTPClient.Configuration.Timeout(connect: connect, read: .seconds(10))
        return c
    }

    private func tlsConfig(minVersion: TLSVersion) -> HTTPClient.Configuration {
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.minimumTLSVersion = minVersion
        var c = HTTPClient.Configuration()
        c.tlsConfiguration = tls
        return c
    }

    // MARK: - configsEquivalentForPooling

    @Test("two default configurations are equivalent")
    func defaultsEquivalent() {
        #expect(
            OPA.HTTPClientCache.configsEquivalentForPooling(
                HTTPClient.Configuration(), HTTPClient.Configuration()))
    }

    @Test("a differing connect timeout is not equivalent")
    func timeoutDiffers() {
        #expect(
            !OPA.HTTPClientCache.configsEquivalentForPooling(
                config(connect: .seconds(1)), config(connect: .seconds(2))))
    }

    @Test("identical TLS settings are equivalent, differing minimum version is not")
    func tlsEquivalence() {
        #expect(
            OPA.HTTPClientCache.configsEquivalentForPooling(
                tlsConfig(minVersion: .tlsv12), tlsConfig(minVersion: .tlsv12)))
        #expect(
            !OPA.HTTPClientCache.configsEquivalentForPooling(
                tlsConfig(minVersion: .tlsv12), tlsConfig(minVersion: .tlsv13)))
    }

    // MARK: - Client reuse / eviction identity

    @Test("same service + equivalent config reuses the same client instance")
    func reuseSameClient() async {
        let cache = OPA.HTTPClientCache()
        let a = cache.client(service: "svc", configuration: config(connect: .seconds(5)))
        let b = cache.client(service: "svc", configuration: config(connect: .seconds(5)))
        #expect(a === b, "an equivalent config must reuse the cached client")
        await cache.shutdownAll()
    }

    @Test("a changed config rebuilds (and evicts) the cached client")
    func rebuildOnChange() async {
        let cache = OPA.HTTPClientCache()
        let a = cache.client(service: "svc", configuration: config(connect: .seconds(5)))
        let b = cache.client(service: "svc", configuration: config(connect: .seconds(9)))
        #expect(a !== b, "a changed config must produce a fresh client")
        await cache.shutdownAll()
    }

    @Test("distinct services get distinct clients")
    func distinctServices() async {
        let cache = OPA.HTTPClientCache()
        let a = cache.client(service: "one", configuration: HTTPClient.Configuration())
        let b = cache.client(service: "two", configuration: HTTPClient.Configuration())
        #expect(a !== b)
        await cache.shutdownAll()
    }

    @Test("evict removes a service's client; a later lookup builds a fresh one")
    func evictThenRebuild() async {
        let cache = OPA.HTTPClientCache()
        let a = cache.client(service: "svc", configuration: HTTPClient.Configuration())
        cache.evict(services: ["svc"])
        let b = cache.client(service: "svc", configuration: HTTPClient.Configuration())
        #expect(a !== b, "after eviction a fresh client must be built")
        await cache.shutdownAll()
    }

    @Test("retainOnly evicts unreferenced services and keeps referenced ones")
    func retainOnlyDropsUnreferenced() async {
        let cache = OPA.HTTPClientCache()
        let keep = cache.client(service: "keep", configuration: HTTPClient.Configuration())
        let drop = cache.client(service: "drop", configuration: HTTPClient.Configuration())

        cache.retainOnly(services: ["keep"])

        // The retained service reuses its client; the dropped one is rebuilt.
        let keepAgain = cache.client(service: "keep", configuration: HTTPClient.Configuration())
        let dropAgain = cache.client(service: "drop", configuration: HTTPClient.Configuration())
        #expect(keepAgain === keep, "retained service should keep its client")
        #expect(dropAgain !== drop, "dropped service should be rebuilt")
        await cache.shutdownAll()
    }

    @Test("evictAll rebuilds every client on next lookup")
    func evictAllRebuilds() async {
        let cache = OPA.HTTPClientCache()
        let a = cache.client(service: "svc", configuration: HTTPClient.Configuration())
        cache.evictAll()
        let b = cache.client(service: "svc", configuration: HTTPClient.Configuration())
        #expect(a !== b, "evictAll must force a rebuild")
        await cache.shutdownAll()
    }

    @Test("dropping the cache without shutdownAll does not trap on client deinit")
    func deinitSafetyNet() async throws {
        do {
            let cache = OPA.HTTPClientCache()
            _ = cache.client(service: "svc", configuration: HTTPClient.Configuration())
            // No explicit shutdown; the cache goes out of scope here and its
            // deinit must shut the client down rather than tripping HTTPClient's
            // "not shut down before deinit" precondition.
        }
        // Give the detached shutdown a moment to complete.
        try await Task.sleep(for: .milliseconds(200))
    }
}
