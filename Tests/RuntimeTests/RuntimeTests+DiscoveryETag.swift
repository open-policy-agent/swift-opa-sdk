import Foundation
import Rego
import Testing

@testable import Runtime

@Suite("RuntimeDiscoveryETagTests")
struct RuntimeDiscoveryETagTests {

    struct TestCase: Sendable, CustomTestStringConvertible {
        let description: String
        let discoveredBundles: [String]
        let expectedSuccessBundles: Set<String>
        var testDescription: String { description }
    }

    static var cases: [TestCase] {
        [
            TestCase(
                description: "Happy path: discovery bundle fetched, regular bundles loaded",
                discoveredBundles: ["b1", "b2"],
                expectedSuccessBundles: ["b1", "b2"]
            ),
            TestCase(
                description: "Discovery lists a single bundle; runtime loads it",
                discoveredBundles: ["only"],
                expectedSuccessBundles: ["only"]
            ),
        ]
    }

    @Test("Discovery + ETag + regular bundles", arguments: cases)
    func runScenario(_ tc: TestCase) async throws {
        let (server, runtime, runTask) = try await startDiscoveryRuntime(
            discovery: DiscoverySpec(discoveredBundles: tc.discoveredBundles),
            bundles: tc.discoveredBundles.map { BundleSpec(name: $0) }
        )
        defer {
            runTask.cancel()
            Task { try? await server.shutdown() }
        }

        try await waitForCondition("activeConfig reflects bundles", timeout: .seconds(15)) {
            let active = await runtime.activeConfig
            return tc.expectedSuccessBundles.allSatisfy { active.bundles[$0] != nil }
        }

        let active = await runtime.activeConfig
        #expect(active.discovery != nil, "[\(tc.description)] discovery retained")

        try await waitForBundleCount(runtime, atLeast: tc.expectedSuccessBundles.count)
        let storage = await runtime.storageSnapshot()
        for name in tc.expectedSuccessBundles {
            expectBundleSucceeded(storage, name, "[\(tc.description)]")
        }
        #expect(storage["discovery"] == nil, "discovery must not be in bundleStorage")

        // If-None-Match on re-polls.
        try await waitForRequests(server, prefix: "/discovery", atLeast: 2)
        let requests = server.state.requests(forURIPrefix: "/discovery")
        let hadIfNoneMatch = requests.dropFirst().contains {
            $0.headerValue(for: "if-none-match") != nil
        }
        #expect(hadIfNoneMatch, "[\(tc.description)] expected If-None-Match on re-poll")
    }

    @Test("Discovery 500: runtime keeps running, active config unchanged")
    func discoveryInitialFailure() async throws {
        let (server, runtime, runTask) = try await startDiscoveryRuntime(
            discovery: DiscoverySpec(etag: nil, forceStatusCode: 500)
        )
        defer {
            runTask.cancel()
            Task { try? await server.shutdown() }
        }

        try await waitForRequests(server, prefix: "/discovery", atLeast: 2, timeout: .seconds(10))

        let active = await runtime.activeConfig
        #expect(active.bundles.isEmpty, "no bundles when discovery fails")
        let storage = await runtime.bundleStorage
        #expect(storage.isEmpty, "no loaders on discovery failure")
    }

    @Test("Discovery succeeds, but one regular bundle endpoint 404s")
    func discoveryPartialBundleFailure() async throws {
        // 'bad' is listed in the discovered config but not registered -> 404.
        let (server, runtime, runTask) = try await startDiscoveryRuntime(
            discovery: DiscoverySpec(discoveredBundles: ["good", "bad"]),
            bundles: [BundleSpec(name: "good")]
        )
        defer {
            runTask.cancel()
            Task { try? await server.shutdown() }
        }

        try await waitForCondition("activeConfig reflects discovered bundles", timeout: .seconds(15)) {
            let active = await runtime.activeConfig
            return active.bundles["good"] != nil && active.bundles["bad"] != nil
        }

        try await waitForBundleCount(runtime, atLeast: 2)
        let storage = await runtime.storageSnapshot()
        expectBundleSucceeded(storage, "good")
        expectBundleFailed(storage, "bad")
        #expect(storage["discovery"] == nil, "discovery must not be in bundleStorage")
    }
}

// MARK: - Discovery Long-Polling Integration Tests

@Suite("Runtime Discovery Long-Polling Tests")
struct RuntimeDiscoveryLongPollingTests {
    static let longPollHeaderName = "prefer"
    static let opaBundleContentType = "application/vnd.openpolicyagent.bundles"

    struct TC: Sendable, CustomStringConvertible {
        let name: String
        let discoveryStatusCode: UInt?
        let discoveryLongPollDelay: Duration
        let discoveryContentType: String
        let longPollingTimeoutSeconds: Int?
        let expectBundleLoaded: Bool
        let expectLongPollHeader: Bool
        let minDiscoveryRequests: Int
        var description: String { name }

        static let all: [TC] = [
            TC(
                name: "Happy path (gzip, no LP configured)",
                discoveryStatusCode: nil, discoveryLongPollDelay: .zero,
                discoveryContentType: "application/gzip",
                longPollingTimeoutSeconds: nil,
                expectBundleLoaded: true, expectLongPollHeader: false,
                minDiscoveryRequests: 1),
            TC(
                name: "Happy path (OPA ct, LP configured)",
                discoveryStatusCode: nil, discoveryLongPollDelay: .seconds(2),
                discoveryContentType: opaBundleContentType,
                longPollingTimeoutSeconds: 5,
                expectBundleLoaded: true, expectLongPollHeader: true,
                minDiscoveryRequests: 2),
            TC(
                name: "Failure (gzip, no LP configured)",
                discoveryStatusCode: 500, discoveryLongPollDelay: .zero,
                discoveryContentType: "application/gzip",
                longPollingTimeoutSeconds: nil,
                expectBundleLoaded: false, expectLongPollHeader: false,
                minDiscoveryRequests: 2),
            TC(
                name: "Failure (OPA ct, LP configured)",
                discoveryStatusCode: 500, discoveryLongPollDelay: .zero,
                discoveryContentType: opaBundleContentType,
                longPollingTimeoutSeconds: 5,
                expectBundleLoaded: false, expectLongPollHeader: false,
                minDiscoveryRequests: 2),
        ]
    }

    @Test("Discovery long-polling scenarios", arguments: TC.all)
    func testDiscoveryLongPolling(tc: TC) async throws {
        let (server, runtime, runTask) = try await startDiscoveryRuntime(
            discovery: DiscoverySpec(
                etag: tc.discoveryStatusCode == nil ? "\"d-lp-1\"" : nil,
                contentType: tc.discoveryContentType,
                forceStatusCode: tc.discoveryStatusCode,
                longPollDelay: tc.discoveryLongPollDelay,
                discoveredBundles: tc.discoveryStatusCode == nil ? ["b1"] : []
            ),
            bundles: [BundleSpec(name: "b1")],
            polling: PollingOptions(longPollingTimeoutSeconds: tc.longPollingTimeoutSeconds)
        )
        defer {
            runTask.cancel()
            Task { try? await server.shutdown() }
        }

        if tc.expectBundleLoaded {
            try await waitForBundleCount(runtime, atLeast: 1, timeout: .seconds(30))
            expectBundleSucceeded(await runtime.storageSnapshot(), "b1")
        } else {
            try await waitForRequests(
                server, prefix: "/discovery", atLeast: tc.minDiscoveryRequests, timeout: .seconds(30)
            )
            let storage = await runtime.bundleStorage
            #expect(storage.isEmpty, "no bundles expected; got \(storage.keys)")
        }

        try await waitForRequests(server, prefix: "/discovery", atLeast: tc.minDiscoveryRequests)
        let requests = server.state.requests(forURIPrefix: "/discovery")
        let sawLongPoll = requests.dropFirst().contains {
            ($0.headerValue(for: Self.longPollHeaderName) ?? "").contains("wait=")
        }
        #expect(
            sawLongPoll == tc.expectLongPollHeader,
            "LP header expectation mismatch for \(tc.discoveryContentType)")
    }
}

// MARK: - Discovery Long-Polling State Transitions

@Suite("Runtime Discovery Long-Polling State Transitions")
struct RuntimeDiscoveryLongPollingStateTransitionTests {
    static let opaCT = "application/vnd.openpolicyagent.bundles"
    static let gzipCT = "application/gzip"

    struct TransitionCase: Sendable, CustomStringConvertible {
        let name: String
        let initialContentType: String
        let switchedContentType: String
        let lpTimeout: Int
        /// Whether the INITIAL steady state should carry `wait=`.
        let initiallyLongPolling: Bool
        /// Whether the POST-SWITCH steady state should carry `wait=`.
        let finallyLongPolling: Bool
        var description: String { name }

        static let all: [TransitionCase] = [
            TransitionCase(
                name: "server stops signaling -> LP disabled",
                initialContentType: opaCT, switchedContentType: gzipCT,
                lpTimeout: 30,
                initiallyLongPolling: true, finallyLongPolling: false
            ),
            TransitionCase(
                name: "server starts signaling -> LP enabled",
                initialContentType: gzipCT, switchedContentType: opaCT,
                lpTimeout: 20,
                initiallyLongPolling: false, finallyLongPolling: true
            ),
        ]
    }

    @Test("LP state flips with server content-type", arguments: TransitionCase.all)
    func testTransition(tc: TransitionCase) async throws {
        let (server, _, runTask) = try await startDiscoveryRuntime(
            discovery: DiscoverySpec(
                etag: "\"v1\"",
                contentType: tc.initialContentType,
                discoveredBundles: ["b1"]
            ),
            bundles: [BundleSpec(name: "b1")],
            polling: PollingOptions(longPollingTimeoutSeconds: tc.lpTimeout)
        )
        defer {
            runTask.cancel()
            Task { try? await server.shutdown() }
        }

        // Observe the INITIAL steady state on request 2+.
        try await waitForRequests(server, prefix: "/discovery", atLeast: 2)
        let initialPrefer =
            server.state.requests(forURIPrefix: "/discovery")[1]
            .headerValue(for: "prefer") ?? ""
        #expect(
            initialPrefer.contains("wait=") == tc.initiallyLongPolling,
            "[\(tc.name)] initial LP state mismatch; prefer=\(initialPrefer)"
        )

        // Flip the server's content-type.
        if let p = server.state.state(for: "/discovery") {
            p.contentType = tc.switchedContentType
            p.etag = "\"v2\""
        }

        // Need two more requests: one to observe the change, one to act on it.
        let baseline = server.state.requests(forURIPrefix: "/discovery").count
        try await waitForRequests(server, prefix: "/discovery", atLeast: baseline + 2)
        let postPrefer =
            server.state.requests(forURIPrefix: "/discovery")[baseline + 1]
            .headerValue(for: "prefer") ?? ""
        #expect(
            postPrefer.contains("wait=\(tc.lpTimeout)") == tc.finallyLongPolling,
            "[\(tc.name)] post-switch LP state mismatch; prefer=\(postPrefer)"
        )
    }

    @Test("ETag + LP interact: 304 works while long-polling is active")
    func testDiscoveryETagAnd304DuringLongPolling() async throws {
        let (server, runtime, runTask) = try await startDiscoveryRuntime(
            discovery: DiscoverySpec(
                etag: "\"combo-v1\"",
                contentType: Self.opaCT,
                discoveredBundles: ["b1"]
            ),
            bundles: [BundleSpec(name: "b1")],
            polling: PollingOptions(longPollingTimeoutSeconds: 30)
        )
        defer {
            runTask.cancel()
            Task { try? await server.shutdown() }
        }

        try await waitForCondition("activeConfig reflects b1", timeout: .seconds(15)) {
            await runtime.activeConfig.bundles["b1"] != nil
        }
        try await waitForRequests(server, prefix: "/discovery", atLeast: 2)

        let repoll = server.state.requests(forURIPrefix: "/discovery")[1]
        #expect((repoll.headerValue(for: "prefer") ?? "").contains("wait=30"))
        #expect(repoll.headerValue(for: "if-none-match") == "\"combo-v1\"")
        #expect(
            await runtime.activeConfig.bundles["b1"] != nil,
            "active config should survive 304")
    }
}

// MARK: - Test harness

/// Spec for a single bundle endpoint registered on the test server.
struct BundleSpec: Sendable {
    let name: String
    let etag: String
    /// If nil, a fresh example bundle is generated.
    let tarball: Data?

    init(name: String, etag: String? = nil, tarball: Data? = nil) {
        self.name = name
        self.etag = etag ?? "\"\(name)-v1\""
        self.tarball = tarball
    }
}

/// Spec for the `/discovery` endpoint.
struct DiscoverySpec: Sendable {
    var etag: String? = "\"disco-v1\""
    var contentType: String = "application/gzip"
    var forceStatusCode: UInt? = nil
    var longPollDelay: Duration = .zero
    /// Bundles that the *discovered config* should list. When status code is
    /// set (failure mode), this is ignored and no discovery bundle is built.
    var discoveredBundles: [String] = []
}

/// Options that shape the boot config's `discovery.polling` block.
struct PollingOptions: Sendable {
    var minDelaySeconds: Int = 1
    var maxDelaySeconds: Int = 1
    var longPollingTimeoutSeconds: Int? = nil

    var json: String {
        var fields = [
            "\"min_delay_seconds\": \(minDelaySeconds)",
            "\"max_delay_seconds\": \(maxDelaySeconds)",
        ]
        if let lp = longPollingTimeoutSeconds {
            fields.append("\"long_polling_timeout_seconds\": \(lp)")
        }
        return "{\n    \(fields.joined(separator: ",\n    "))\n}"
    }
}

/// Spins up a test server + runtime configured for discovery. Returns both
/// so tests can inspect requests and runtime state, plus a cleanup closure.
@discardableResult
func startDiscoveryRuntime(
    discovery: DiscoverySpec,
    bundles: [BundleSpec] = [],
    polling: PollingOptions = PollingOptions()
) async throws -> (server: TestBundleServer, runtime: OPA.Runtime, runTask: Task<Void, Error>) {
    // Register bundle endpoints.
    var paths: [String: PathState] = [:]
    for b in bundles {
        let data = try b.tarball ?? OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        paths["/bundles/\(b.name)"] = PathState(
            data: data, etag: b.etag, contentType: "application/gzip"
        )
    }

    // Register /discovery with placeholder data; we overwrite once the
    // server is running (we need its baseURL for the `services` block).
    paths["/discovery"] = PathState(
        data: Data(),
        etag: discovery.etag,
        forceStatusCode: discovery.forceStatusCode,
        contentType: discovery.contentType,
        longPollDelay: discovery.longPollDelay
    )

    let server = try await TestBundleServer.start(paths: paths)

    // If discovery is expected to succeed, install the real tarball.
    if discovery.forceStatusCode == nil && !discovery.discoveredBundles.isEmpty {
        let configJSON = discoveryConfigJSON(
            bundleNames: discovery.discoveredBundles,
            serviceURL: server.baseURL
        )
        let discoveryBundle = try makeDiscoveryBundle(
            decisionPath: "discovery/config",
            configDataPath: "discovery/config",
            configJSON: configJSON
        )
        let discoveryTarball = try OPA.Bundle.encodeToTarball(bundle: discoveryBundle)
        server.state.state(for: "/discovery")?.data = discoveryTarball
    }

    // Build boot config + runtime.
    let bootConfigJSON = """
        {
            "services": {"svc": {"url": "\(server.baseURL)"}},
            "discovery": {
                "service": "svc",
                "resource": "/discovery",
                "decision": "discovery/config",
                "polling": \(polling.json)
            }
        }
        """
    let bootConfig = try JSONDecoder().decode(
        OPA.Config.self, from: Data(bootConfigJSON.utf8))
    let runtime = try OPA.Runtime(config: bootConfig)
    let runTask = Task { try await runtime.run() }
    return (server, runtime, runTask)
}

/// Discovery config JSON with a `services` section so the discovered config
/// passes standalone validation.
func discoveryConfigJSON(bundleNames: [String], serviceURL: String) -> String {
    let entries = bundleNames.map { name in
        #""\#(name)": {"service": "svc", "resource": "/bundles/\#(name)"}"#
    }.joined(separator: ",\n        ")
    return """
        {
            "services": {"svc": {"url": "\(serviceURL)"}},
            "bundles": {
                \(entries)
            }
        }
        """
}

// MARK: - Helpers

struct WaitTimeoutError: Error, CustomStringConvertible {
    let message: String
    var description: String { message }
}

func waitForCondition(
    _ label: String = "condition",
    timeout: Duration = .seconds(15),
    _ predicate: @Sendable () async -> Bool
) async throws {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        if await predicate() { return }
        try await Task.sleep(for: .milliseconds(100))
    }
    throw WaitTimeoutError(message: "waitForCondition('\(label)') timed out after \(timeout)")
}

func waitForBundleCount(
    _ runtime: OPA.Runtime, atLeast n: Int, timeout: Duration = .seconds(15)
) async throws {
    try await waitForCondition("bundle count >= \(n)", timeout: timeout) {
        await runtime.bundleStorage.count >= n
    }
}

func waitForRequests(
    _ server: TestBundleServer, prefix: String, atLeast n: Int,
    timeout: Duration = .seconds(15)
) async throws {
    try await waitForCondition("\(prefix) requests >= \(n)", timeout: timeout) {
        server.state.requests(forURIPrefix: prefix).count >= n
    }
}

// MARK: - Storage assertion helpers

extension OPA.Runtime {
    /// Snapshots current bundleStorage for concise assertions in tests.
    func storageSnapshot() async -> [String: Result<OPA.Bundle, Error>] {
        return bundleStorage
    }
}

func expectBundleSucceeded(
    _ storage: [String: Result<OPA.Bundle, Error>],
    _ name: String,
    _ context: String = ""
) {
    switch storage[name] {
    case .some(.success): return
    case .some(.failure(let err)):
        Issue.record("\(context) bundle '\(name)' expected success, got failure: \(err)")
    case .none:
        Issue.record("\(context) bundle '\(name)' missing from storage")
    }
}

func expectBundleFailed(
    _ storage: [String: Result<OPA.Bundle, Error>],
    _ name: String,
    _ context: String = ""
) {
    switch storage[name] {
    case .some(.failure): return
    case .some(.success):
        Issue.record("\(context) bundle '\(name)' expected failure, got success")
    case .none:
        Issue.record("\(context) bundle '\(name)' missing from storage")
    }
}
