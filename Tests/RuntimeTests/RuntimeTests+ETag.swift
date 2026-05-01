import Foundation
import Rego
import Testing

// MARK: - End-to-End Runtime ETag Integration Tests

@Suite("Runtime ETag Integration Tests")
struct RuntimeETagIntegrationTests {

    @Test("Runtime polling gracefully handles 304 Not Modified")
    func testRuntimePollingWith304() async throws {
        try await withBundleServer(etag: "\"rt-v1\"") { server in
            let configJSON = makeETagTestConfigWithPolling(baseURL: server.baseURL)

            try await withRunningRuntime(server: server, configJSON: configJSON) { rt in
                try await Task.sleep(for: .seconds(3))

                let latestStorage = await rt.bundleStorage
                guard case .success = latestStorage["test"] else {
                    Issue.record("Bundle 'test' should still be .success after polling")
                    return
                }

                let requests = server.state.requests
                #expect(
                    requests.count >= 2,
                    "Expected at least 2 requests (initial + poll), got \(requests.count)")
            }
        }
    }

    @Test("Runtime picks up a new bundle when the server updates content and ETag")
    func testRuntimePicksUpNewBundle() async throws {
        try await withBundleServer(etag: "\"rt-v1\"") { server in
            let configJSON = makeETagTestConfigWithPolling(baseURL: server.baseURL)
            try await withRunningRuntime(server: server, configJSON: configJSON) { rt in
                let firstBundle = await rt.bundles["test"]
                #expect(firstBundle != nil)

                server.state.bundleData = try makeBundleData()
                server.state.etag = "\"rt-v2\""

                try await Task.sleep(for: .seconds(3))

                let updatedBundle = await rt.bundles["test"]
                #expect(updatedBundle != nil)
                #expect(updatedBundle != firstBundle, "Runtime should have picked up the new bundle")
            }
        }
    }
}

// MARK: - Long-Polling Loader Tests

@Suite("RESTClientBundleLoader Long-Polling State Transitions")
struct RESTClientLongPollingStateTransitionTests {

    static let opaBundleContentType = "application/vnd.openpolicyagent.bundles"

    @Test("Long polling is disabled when server stops signaling support")
    func testLongPollingDisabledWhenServerStopsSignaling() async throws {
        try await withBundleServer(etag: "\"lp-v1\"", contentType: Self.opaBundleContentType) { server in
            var loader = try makeRESTClientBundleLoader(
                configJSON: makeETagTestConfigWithLongPolling(
                    baseURL: server.baseURL, longPollingTimeoutSeconds: 30)
            )

            // Load 1: enables long-polling from response content-type.
            _ = await loader.load()

            // Load 2: long-polling should be active.
            _ = await loader.load()
            let req2Prefer = server.state.requests[1].headerValue(for: "prefer") ?? ""
            #expect(
                req2Prefer.contains("wait=30"),
                "Request 2 should have wait= (long-polling active), got: \(req2Prefer)")

            // Server switches to regular content-type.
            server.state.responseContentType = "application/gzip"
            server.state.etag = "\"lp-v2\""

            // Load 3: gets 200 with regular content-type -> disables long-polling.
            _ = await loader.load()

            // Load 4: long-polling should now be OFF.
            server.state.forceStatusCode = 304
            _ = await loader.load()
            server.state.forceStatusCode = nil

            let req4Prefer = server.state.requests[3].headerValue(for: "prefer") ?? ""
            #expect(
                !req4Prefer.contains("wait="),
                "Request 4 should NOT have wait= after server stopped signaling, got: \(req4Prefer)")
        }
    }

    @Test("Long polling is re-enabled when server resumes signaling support")
    func testLongPollingReEnabledWhenServerResumesSignaling() async throws {
        try await withBundleServer(etag: "\"v1\"", contentType: "application/gzip") { server in
            var loader = try makeRESTClientBundleLoader(
                configJSON: makeETagTestConfigWithLongPolling(
                    baseURL: server.baseURL, longPollingTimeoutSeconds: 20)
            )

            // Load 1 & 2: regular content-type, no long-polling.
            _ = await loader.load()
            _ = await loader.load()
            let req2Prefer = server.state.requests[1].headerValue(for: "prefer") ?? ""
            #expect(!req2Prefer.contains("wait="), "Request 2 should have no wait= yet")

            // Server starts signaling long-polling support.
            server.state.responseContentType = Self.opaBundleContentType
            server.state.etag = "\"v2\""

            // Load 3: picks up OPA content-type -> enables long-polling.
            _ = await loader.load()

            // Load 4: should now include wait=.
            server.state.forceStatusCode = 304
            _ = await loader.load()
            server.state.forceStatusCode = nil

            let req4Prefer = server.state.requests[3].headerValue(for: "prefer") ?? ""
            #expect(
                req4Prefer.contains("wait=20"),
                "Request 4 should have wait=20 after re-enable, got: \(req4Prefer)")
        }
    }

    @Test("ETag and long-polling interact correctly: 304 works while long-polling is active")
    func testETagAnd304WorkDuringLongPolling() async throws {
        try await withBundleServer(etag: "\"combo-v1\"", contentType: Self.opaBundleContentType) { server in
            var loader = try makeRESTClientBundleLoader(
                configJSON: makeETagTestConfigWithLongPolling(
                    baseURL: server.baseURL, longPollingTimeoutSeconds: 30)
            )

            let firstResult = await loader.load()
            guard case .success(let originalBundle) = firstResult else {
                Issue.record("Expected .success on first load, got \(firstResult)")
                return
            }
            #expect(loader.etag == "\"combo-v1\"")

            server.state.forceStatusCode = 304
            let secondResult = await loader.load()
            server.state.forceStatusCode = nil

            guard case .success(let cachedBundle) = secondResult else {
                Issue.record("Expected .success on 304 during long-polling, got \(secondResult)")
                return
            }
            #expect(cachedBundle == originalBundle)

            let req2Prefer = server.state.requests[1].headerValue(for: "prefer") ?? ""
            #expect(
                req2Prefer.contains("wait=30"),
                "304 request during long-polling should have wait=, got: \(req2Prefer)")
        }
    }
}

// MARK: - Long-Polling Prefer Header Integration Tests

struct PreferHeaderExpectation: Sendable {
    /// Whether `wait=` should appear in the prefer header.
    let shouldContainWait: Bool
    /// If `shouldContainWait`, the exact value expected (e.g. 30 -> "wait=30").
    let expectedWaitValue: Int?

    static func wait(_ value: Int) -> Self {
        .init(shouldContainWait: true, expectedWaitValue: value)
    }
    static var noWait: Self {
        .init(shouldContainWait: false, expectedWaitValue: nil)
    }
}

@Suite("RESTClientBundleLoader Long-Polling Prefer Header Tests")
struct RESTClientLongPollingPreferHeaderTests {
    struct PreferHeaderTestCase: Sendable, CustomStringConvertible {
        let name: String
        let serverContentType: String
        let longPollingTimeout: Int?  // nil -> use polling config (no LP)
        /// One entry per load. Loads after the first are forced to 304.
        let expectations: [PreferHeaderExpectation]

        var description: String { name }

        static let allCases: [PreferHeaderTestCase] = [
            PreferHeaderTestCase(
                name: "First request never includes wait, even with LP configured",
                serverContentType: opaBundleContentType,
                longPollingTimeout: 30,
                expectations: [.noWait]
            ),
            PreferHeaderTestCase(
                name: "Second request includes wait= after server signals LP support",
                serverContentType: opaBundleContentType,
                longPollingTimeout: 45,
                expectations: [.noWait, .wait(45)]
            ),
            PreferHeaderTestCase(
                name: "Prefer header wait value matches configured timeout",
                serverContentType: opaBundleContentType,
                longPollingTimeout: 97,
                expectations: [.noWait, .wait(97)]
            ),
            PreferHeaderTestCase(
                name: "LP not activated when server does not signal support",
                serverContentType: "application/gzip",
                longPollingTimeout: 30,
                expectations: [.noWait, .noWait]
            ),
            PreferHeaderTestCase(
                name: "LP not activated when config has no timeout",
                serverContentType: opaBundleContentType,
                longPollingTimeout: nil,
                expectations: [.noWait, .noWait]
            ),
            // Can't test zero timeout for long-polling, because config will fail validation.
        ]

        private static let opaBundleContentType = "application/vnd.openpolicyagent.bundles"
    }

    @Test("Long-Polling Prefer header tests", arguments: PreferHeaderTestCase.allCases)
    func testPreferHeader(tc: PreferHeaderTestCase) async throws {
        try await withBundleServer(etag: "\"lp-v1\"", contentType: tc.serverContentType) { server in
            let configJSON: String
            if let timeout = tc.longPollingTimeout {
                configJSON = makeETagTestConfigWithLongPolling(
                    baseURL: server.baseURL, longPollingTimeoutSeconds: timeout
                )
            } else {
                configJSON = makeETagTestConfigWithPolling(baseURL: server.baseURL)
            }

            var loader = try makeRESTClientBundleLoader(configJSON: configJSON)

            for (i, expectation) in tc.expectations.enumerated() {
                // Force 304 on all loads after the first.
                if i > 0 { server.state.forceStatusCode = 304 }
                let _ = await loader.load()
                if i > 0 { server.state.forceStatusCode = nil }

                let prefer = server.state.requests[i].headerValue(for: "prefer") ?? ""
                #expect(prefer.contains("modes="), "Request \(i): prefer should always include modes=")

                if expectation.shouldContainWait {
                    let waitStr = "wait=\(expectation.expectedWaitValue!)"
                    #expect(
                        prefer.contains(waitStr),
                        "Request \(i): expected \(waitStr), got: \(prefer)")
                } else {
                    #expect(
                        !prefer.contains("wait="),
                        "Request \(i): should NOT include wait=, got: \(prefer)")
                }
            }
        }
    }
}

// MARK: - Helpers

// Add near the other free-function helpers (makeExampleBundle, etc.)
func makeBundleData() throws -> Data {
    let bundle = try makeExampleBundle()
    return try OPA.Bundle.encodeToTarball(bundle: bundle)
}

func withBundleServer(
    etag: String = "\"v1\"",
    contentType: String = "application/gzip",
    _ body: (TestBundleServer) async throws -> Void
) async throws {
    let bundleData = try makeBundleData()
    let server = try await TestBundleServer.start(
        bundleData: bundleData, etag: etag, contentType: contentType
    )
    do {
        try await body(server)
        try? await server.shutdown()
    } catch {
        try? await server.shutdown()
        throw error
    }
}

func withRunningRuntime(
    server: TestBundleServer,
    configJSON: String,
    bundleName: String = "test",
    _ body: (OPA.Runtime) async throws -> Void
) async throws {
    let config = try JSONDecoder().decode(OPA.Config.self, from: configJSON.data(using: .utf8)!)
    let rt = try OPA.Runtime(config: config)

    let backgroundTask = Task { try await rt.run() }
    defer { backgroundTask.cancel() }

    let _ = await waitForBundleLoad(rt: rt, name: bundleName, timeout: .seconds(5))

    let storage = await rt.bundleStorage
    guard case .success = storage[bundleName] else {
        Issue.record("Expected bundle '\(bundleName)' to be .success, got \(String(describing: storage[bundleName]))")
        return
    }

    try await body(rt)
}
