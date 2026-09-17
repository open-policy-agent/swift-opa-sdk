import AST
import Foundation
import Rego
import Testing

// MARK: - Loader-Level ETag Tests

@Suite("RESTClientBundleLoader ETag Tests")
struct RESTClientETagTests {

    // MARK: Valid / Success Cases

    @Test("Initial request does not include If-None-Match header")
    func testFirstRequestHasNoIfNoneMatch() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))
            let _ = try requireBundleLoadSuccess(await loader.load())

            let requests = server.state.requests
            #expect(requests.count == 1)
            #expect(requests[0].headerValue(for: "If-None-Match") == nil)
        }
    }

    @Test("ETag from server response is stored on the loader")
    func testETagStoredFromResponse() async throws {
        try await withBundleServer(etag: "\"abc-123\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))
            #expect(loader.etag == "")

            let _ = await loader.load()

            #expect(loader.etag == "\"abc-123\"")
        }
    }

    @Test("Second request sends If-None-Match header with stored ETag")
    func testIfNoneMatchSentOnSubsequentRequest() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let _ = await loader.load()
            #expect(loader.etag == "\"v1\"")

            let _ = await loader.load()

            let requests = server.state.requests
            #expect(requests.count == 2)
            #expect(requests[1].headerValue(for: "If-None-Match") == "\"v1\"")
        }
    }

    @Test("304 returns .notModified and preserves the loader's ETag")
    func testNotModifiedReturnedOn304() async throws {
        try await withBundleServer(etag: "\"rev-1\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let _ = try requireBundleLoadSuccess(await loader.load(), context: "on first load")
            server.state.forceStatusCode = 304
            let secondResult = await loader.load()
            server.state.forceStatusCode = nil

            guard case .notModified(let etag) = secondResult else {
                Issue.record("Expected .notModified on 304, got \(secondResult)")
                return
            }
            #expect(etag == "\"rev-1\"")
        }
    }

    @Test("New bundle with a different ETag replaces the cached bundle")
    func testNewBundleReplacesOldBundle() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let loadedA = try requireBundleLoadSuccess(await loader.load(), context: "on first load")
            #expect(loader.etag == "\"v1\"")

            // Swap to a new bundle with a new etag on the server.
            server.state.bundleData = try makeBundleData()
            server.state.etag = "\"v2\""

            let loadedB = try requireBundleLoadSuccess(await loader.load(), context: "on second load")
            #expect(loader.etag == "\"v2\"")
            #expect(loadedA != loadedB)
        }
    }

    @Test("ETag is cleared to empty string when server omits it")
    func testETagClearedWhenAbsent() async throws {
        try await withBundleServer(etag: "\"initial\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let _ = await loader.load()
            #expect(loader.etag == "\"initial\"")

            server.state.etag = nil

            let _ = try requireBundleLoadSuccess(await loader.load(), context: "on second load")
            #expect(loader.etag == "")
        }
    }

    @Test("ETag can be pre-seeded via the HTTPBundleLoader initializer")
    func testPreSeededETag() async throws {
        try await withBundleServer(etag: "\"pre-seed\"") { server in
            let loader = try makeRESTClientBundleLoader(
                configJSON: makeETagTestConfig(baseURL: server.baseURL),
                etag: "\"pre-seed\""
            )
            #expect(loader.etag == "\"pre-seed\"")
        }
    }

    @Test("Multiple sequential 304s each return .notModified")
    func testMultiple304sReturnNotModified() async throws {
        try await withBundleServer(etag: "\"stable\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let _ = try requireBundleLoadSuccess(await loader.load(), context: "on first load")
            server.state.forceStatusCode = 304
            for i in 1...3 {
                let result = await loader.load()
                guard case .notModified(let etag) = result else {
                    Issue.record("Round \(i): expected .notModified, got \(result)")
                    return
                }
                #expect(etag == "\"stable\"", "Round \(i): etag should be preserved")
            }
        }
    }

    // MARK: Invalid / Failure Cases

    @Test("304 on a fresh loader returns .notModified")
    func test304OnFreshLoaderReturnsNotModified() async throws {
        let server = try await TestBundleServer.start(
            bundleData: Data(), etag: "\"orphan\"", forceStatusCode: 304
        )
        defer { Task { try? await server.shutdown() } }

        var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

        // The loader no longer caches bundles or distinguishes a 304 without a
        // prior success; it simply reports .notModified. The runtime's
        // BundleStore records the "304 with nothing active" case as an error.
        let result = await loader.load()
        guard case .notModified = result else {
            Issue.record("Expected .notModified on a forced 304, got \(result)")
            return
        }
    }

    @Test("500 then 304: first fails, then reports .notModified")
    func test500ThenNotModified() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            server.state.forceStatusCode = 500
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let firstResult = await loader.load()
            guard case .failed = firstResult else {
                Issue.record("Expected .failed on first load (server returned 500), got \(firstResult)")
                return
            }

            server.state.forceStatusCode = 304
            let secondResult = await loader.load()
            guard case .notModified = secondResult else {
                Issue.record("Expected .notModified on 304, got \(secondResult)")
                return
            }
        }
    }

    @Test("Recovery after a forced 304: subsequent 200 succeeds")
    func testRecoveryAfter304() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            server.state.forceStatusCode = 304
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let firstResult = await loader.load()
            guard case .notModified = firstResult else {
                Issue.record("Expected .notModified on forced 304, got \(firstResult)")
                return
            }

            server.state.forceStatusCode = nil
            let _ = try requireBundleLoadSuccess(await loader.load(), context: "after server recovery")
            #expect(loader.etag == "\"v1\"")
        }
    }
}
