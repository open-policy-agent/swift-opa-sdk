import AsyncHTTPClient
import Foundation
import NIOConcurrencyHelpers  // NIOLockedValueBox
import Rego
import Testing

@testable import Runtime

// MARK: - Connection-reuse tests
//
// These assert connection pooling behavior end-to-end via `TestBundleServer`,
// which counts distinct accepted TCP connections. They require binding a
// listening socket.

@Suite("HTTPClientCacheConnectionReuseTests")
struct HTTPClientCacheConnectionReuseTests {

    private func startServer() async throws -> (TestBundleServer, OPA.Config) {
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        let server = try await TestBundleServer.start(files: ["/bundles/test.tar.gz": bundleData])
        let config = try JSONDecoder().decode(
            OPA.Config.self, from: Data(makeETagTestConfig(baseURL: server.baseURL).utf8))
        return (server, config)
    }

    @Test("a cache reuses one connection across repeated loads")
    func poolsConnectionAcrossLoads() async throws {
        let (server, config) = try await startServer()
        defer { Task { try? await server.shutdown() } }
        let cache = OPA.HTTPClientCache()
        defer { Task { await cache.shutdownAll() } }

        var loader = try OPA.RESTClientBundleLoader(
            config: config, bundleResourceName: "test", httpClientCache: cache)
        for _ in 0..<3 { _ = await loader.load() }

        #expect(server.state.requests.count >= 3, "expected repeated polls")
        #expect(server.state.connectionCount == 1, "a cached client should reuse one connection")
    }

    @Test("without a cache each load opens a fresh connection")
    func ephemeralOpensConnectionPerLoad() async throws {
        let (server, config) = try await startServer()
        defer { Task { try? await server.shutdown() } }

        // No cache injected: ephemeral client per load.
        var loader = try OPA.RESTClientBundleLoader(config: config, bundleResourceName: "test")
        for _ in 0..<3 { _ = await loader.load() }

        #expect(server.state.connectionCount == 3, "ephemeral clients should not reuse connections")
    }

    @Test("a closure-based config source is still cacheable when its config is unchanging")
    func closureConfigSourceIsCacheable() async throws {
        let (server, config) = try await startServer()
        defer { Task { try? await server.shutdown() } }
        let cache = OPA.HTTPClientCache()
        defer { Task { await cache.shutdownAll() } }

        // The `.configuration` provider is invoked on every load but returns an
        // unchanging config, so the client should still be reused.
        let source: OPA.HTTPClientConfigSource = .configuration { HTTPClient.Configuration() }
        var loader = try OPA.RESTClientBundleLoader(
            config: config, bundleResourceName: "test",
            httpClientConfig: source, httpClientCache: cache)
        for _ in 0..<3 { _ = await loader.load() }

        #expect(server.state.connectionCount == 1, "an unchanging closure config should reuse one connection")
    }

    @Test("a changed resolved config rebuilds the client, opening a new connection")
    func changedConfigRebuildsConnection() async throws {
        let (server, config) = try await startServer()
        defer { Task { try? await server.shutdown() } }
        let cache = OPA.HTTPClientCache()
        defer { Task { await cache.shutdownAll() } }

        // Return an unchanging config for the first two loads, then a config
        // with a different timeout, which must evict + rebuild the client.
        let loadCount = NIOLockedValueBox(0)
        let source: OPA.HTTPClientConfigSource = .configuration {
            let n = loadCount.withLockedValue { value -> Int in
                value += 1
                return value
            }
            var c = HTTPClient.Configuration()
            if n >= 3 {
                c.timeout = HTTPClient.Configuration.Timeout(connect: .seconds(7), read: .seconds(7))
            }
            return c
        }
        var loader = try OPA.RESTClientBundleLoader(
            config: config, bundleResourceName: "test",
            httpClientConfig: source, httpClientCache: cache)
        for _ in 0..<3 { _ = await loader.load() }

        #expect(
            server.state.connectionCount == 2,
            "the config change on the third load should open exactly one additional connection")
    }
}
