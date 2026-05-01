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

    @Test("Cached bundle is returned when server responds 304")
    func testCachedBundleReturnedOn304() async throws {
        try await withBundleServer(etag: "\"rev-1\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let firstBundle = try requireBundleLoadSuccess(await loader.load(), context: "on first load")
            server.state.forceStatusCode = 304
            let secondBundle = try requireBundleLoadSuccess(await loader.load(), context: "on second (304) load")
            server.state.forceStatusCode = nil

            #expect(firstBundle == secondBundle)
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

    @Test("Multiple sequential 304s return the same cached bundle each time")
    func testMultiple304sReturnSameBundle() async throws {
        try await withBundleServer(etag: "\"stable\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let originalBundle = try requireBundleLoadSuccess(await loader.load(), context: "on first load")
            server.state.forceStatusCode = 304
            for i in 1...3 {
                let cachedBundle = try requireBundleLoadSuccess(await loader.load(), context: "on 304 round \(i)")
                #expect(cachedBundle == originalBundle, "Round \(i): cached bundle should match original")
            }
        }
    }

    // MARK: Invalid / Failure Cases

    @Test("304 without a previously cached bundle produces a failure")
    func test304WithoutCachedBundleFails() async throws {
        let server = try await TestBundleServer.start(
            bundleData: Data(), etag: "\"orphan\"", forceStatusCode: 304
        )
        defer { Task { try? await server.shutdown() } }

        var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

        let result = await loader.load()
        guard case .failure(let error) = result else {
            Issue.record("Expected .failure when 304 arrives with no cached bundle, got \(result)")
            return
        }

        #expect(
            String(describing: error).contains("304"),
            "Error should mention the 304 status code"
        )
    }

    @Test("304 after a failed first load produces a failure")
    func test304AfterPreviousFailureStillFails() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            server.state.forceStatusCode = 500
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let firstResult = await loader.load()
            guard case .failure = firstResult else {
                Issue.record("Expected .failure on first load (server returned 500)")
                return
            }

            server.state.forceStatusCode = 304
            let secondResult = await loader.load()
            guard case .failure = secondResult else {
                Issue.record("Expected .failure on 304 with no cached bundle, got \(secondResult)")
                return
            }
        }
    }

    @Test("Recovery after 304-without-cache: subsequent 200 succeeds")
    func testRecoveryAfter304Failure() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            server.state.forceStatusCode = 304
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let firstResult = await loader.load()
            guard case .failure = firstResult else {
                Issue.record("Expected .failure on forced 304")
                return
            }

            server.state.forceStatusCode = nil
            let _ = try requireBundleLoadSuccess(await loader.load(), context: "after server recovery")
            #expect(loader.etag == "\"v1\"")
        }
    }
}
