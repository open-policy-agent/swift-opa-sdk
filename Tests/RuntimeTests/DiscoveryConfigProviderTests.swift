import AST
import Foundation
import Rego
import Testing

@testable import Runtime

@Suite("DiscoveryConfigProviderTests")
struct DiscoveryConfigProviderTests {

    // MARK: - Init Tests

    @Suite("Init")
    struct InitTests {

        @Test("Rejects config without discovery section")
        func noDiscoverySection() async throws {
            let configJSON = """
                {
                    "services": {
                        "acmecorp": { "url": "https://example.com" }
                    }
                }
                """
            let config: OPA.Config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))

            #expect(throws: (any Error).self) {
                _ = try OPA.DiscoveryConfigProvider(bootConfig: config)
            }
        }

        @Test("Rejects config without discovery section via init(config:)")
        func noDiscoverySectionViaProtocolInit() async throws {
            let configJSON = """
                {
                    "services": {
                        "acmecorp": { "url": "https://example.com" }
                    }
                }
                """
            let config: OPA.Config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))

            #expect(throws: (any Error).self) {
                _ = try OPA.DiscoveryConfigProvider(config: config)
            }
        }

        @Test("Rejects config without a compatible loader")
        func noCompatibleLoader() async throws {
            // Discovery section references a service with an unsupported scheme
            // (or no matching service entry at all).
            let configJSON = """
                {
                    "services": {},
                    "discovery": {
                        "service": "missing-service",
                        "resource": "/discovery"
                    }
                }
                """
            let config: OPA.Config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))

            #expect(throws: (any Error).self) {
                _ = try OPA.DiscoveryConfigProvider(bootConfig: config)
            }
        }

        @Test("Propagates loader init errors")
        func loaderInitErrorPropagates() async throws {
            // ASSUMPTION: a malformed service URL (or similar) causes the
            // bundle loader's initializer to throw, and that error surfaces here.
            let configJSON = """
                {
                    "services": {
                        "acmecorp": { "url": "not a valid url ::::" }
                    },
                    "discovery": {
                        "service": "acmecorp",
                        "resource": "/discovery"
                    }
                }
                """

            #expect(throws: (any Error).self) {
                let config: OPA.Config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))
                _ = try OPA.DiscoveryConfigProvider(bootConfig: config)
            }
        }

        @Test("Happy-path construction succeeds")
        func happyPath() async throws {
            let configJSON = """
                {
                    "services": {
                        "acmecorp": { "url": "https://example.com" }
                    },
                    "discovery": {
                        "service": "acmecorp",
                        "resource": "/discovery"
                    }
                }
                """
            let config: OPA.Config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))
            _ = try OPA.DiscoveryConfigProvider(bootConfig: config)
        }
    }

    // MARK: - Load Tests

    @Suite("Load")
    struct LoadTests {

        init() {
            // These tests construct a DiscoveryConfigProvider directly
            // and call `.load()` without going through the usual
            // `makeExampleBundle` / `TestBundleServer.start` path that
            // triggers the logging bootstrap, so we install the silent
            // handler here explicitly.
            TestLogging.ensureBootstrapped()
        }

        enum ExpectedResult: Sendable {
            case success(configJSON: String)
            case failure
        }

        enum LoaderAction: Sendable {
            case succeedWithConfigJSON(String)
            case fail
        }

        struct TestCase: Sendable {
            let description: String
            let bootConfigTemplate: String  // contains "__MOCK_ID__" placeholder
            let decisionPath: String
            let loaderActions: [LoaderAction]
            let expectedResults: [ExpectedResult]
        }

        // MARK: Fixtures

        /// Boot config template. `__MOCK_ID__` is substituted per-test.
        static let bootConfigTemplate = """
            {
                "services": {
                    "acmecorp": { "url": "https://example.com" }
                },
                "discovery": {
                    "service": "acmecorp",
                    "resource": "/discovery",
                    "decision": "discovery/config",
                    "polling": {
                        "min_delay_seconds": 1,
                        "max_delay_seconds": 1
                    }
                },
                "plugins": {
                    "mock_loader": { "id": "__MOCK_ID__" }
                }
            }
            """

        static let discoveredConfigA = """
            {
                "services": {
                    "discovered-svc": { "url": "https://discovered.example.com" }
                },
                "labels": { "env": "prod" }
            }
            """

        static let discoveredConfigB = """
            {
                "services": {
                    "another-svc": { "url": "https://another.example.com" }
                },
                "labels": { "env": "staging" }
            }
            """

        /// Boot ⊕ discoveredA. Boot wins on conflicts; discovery section preserved.
        static func mergedConfigA(mockID: String) -> String {
            """
            {
                "services": {
                    "acmecorp": { "url": "https://example.com" },
                    "discovered-svc": { "url": "https://discovered.example.com" }
                },
                "labels": { "env": "prod" },
                "discovery": {
                    "service": "acmecorp",
                    "resource": "/discovery",
                    "decision": "discovery/config",
                    "polling": {
                        "min_delay_seconds": 1,
                        "max_delay_seconds": 1
                    }
                },
                "plugins": {
                    "mock_loader": { "id": "\(mockID)" }
                }
            }
            """
        }

        static func mergedConfigB(mockID: String) -> String {
            """
            {
                "services": {
                    "acmecorp": { "url": "https://example.com" },
                    "another-svc": { "url": "https://another.example.com" }
                },
                "labels": { "env": "staging" },
                "discovery": {
                    "service": "acmecorp",
                    "resource": "/discovery",
                    "decision": "discovery/config",
                    "polling": {
                        "min_delay_seconds": 1,
                        "max_delay_seconds": 1
                    }
                },
                "plugins": {
                    "mock_loader": { "id": "\(mockID)" }
                }
            }
            """
        }

        // MARK: Test Cases

        static let cases: [TestCase] = [
            TestCase(
                description: "Successful load returns merged config",
                bootConfigTemplate: bootConfigTemplate,
                decisionPath: "discovery/config",
                loaderActions: [.succeedWithConfigJSON(discoveredConfigA)],
                expectedResults: [.success(configJSON: "__MERGED_A__")]
            ),
            TestCase(
                description: "Failed load returns failure",
                bootConfigTemplate: bootConfigTemplate,
                decisionPath: "discovery/config",
                loaderActions: [.fail],
                expectedResults: [.failure]
            ),
            TestCase(
                description: "Multiple loads with changing results",
                bootConfigTemplate: bootConfigTemplate,
                decisionPath: "discovery/config",
                loaderActions: [
                    .succeedWithConfigJSON(discoveredConfigA),
                    .fail,
                    .succeedWithConfigJSON(discoveredConfigB),
                ],
                expectedResults: [
                    .success(configJSON: "__MERGED_A__"),
                    .failure,
                    .success(configJSON: "__MERGED_B__"),
                ]
            ),
        ]

        // MARK: Runner

        @Test("Load scenarios", arguments: cases)
        func runScenario(tc: TestCase) async throws {
            // Build scripted bundle results.
            let scripted: [Result<OPA.Bundle, any Error>] = try tc.loaderActions.map { action in
                switch action {
                case .succeedWithConfigJSON(let cfgJSON):
                    let bundle = try makeDiscoveryBundle(
                        decisionPath: tc.decisionPath,
                        configDataPath: "my/discovery/data/path",
                        configJSON: cfgJSON)
                    return .success(bundle)
                case .fail:
                    return .failure(
                        RuntimeError(code: .internalError, message: "scripted loader failure"))
                }
            }

            // Register script in the shared registry; clean up at end.
            let mockID = MockBundleLoaderRegistry.shared.register(scripted: scripted)
            defer { MockBundleLoaderRegistry.shared.unregister(id: mockID) }

            // Substitute the ID into the boot config and into the expected
            // merged-config JSON placeholders.
            let bootConfigJSON = tc.bootConfigTemplate.replacingOccurrences(
                of: "__MOCK_ID__", with: mockID)
            let bootConfig = try JSONDecoder().decode(
                OPA.Config.self, from: Data(bootConfigJSON.utf8))

            // Resolve expected configs (substituting the mock ID).
            let resolvedExpected: [ExpectedResult] = tc.expectedResults.map { y in
                switch y {
                case .success(let configJSON):
                    let resolved =
                        configJSON
                        .replacingOccurrences(of: "__MERGED_A__", with: Self.mergedConfigA(mockID: mockID))
                        .replacingOccurrences(of: "__MERGED_B__", with: Self.mergedConfigB(mockID: mockID))
                    return .success(configJSON: resolved)
                case .failure:
                    return .failure
                }
            }

            // Construct provider via the public init path, forcing our mock loader.
            var provider = try OPA.DiscoveryConfigProvider(
                bootConfig: bootConfig,
                bundleLoaders: [OPA.MockBundleLoader.self]
            )

            // Drive load() once per scripted action. The Runtime's polling
            // loop would do this in production; here we call it directly to
            // validate per-call semantics.
            var received: [Result<OPA.Config, Error>] = []
            for _ in 0..<tc.loaderActions.count {
                let result = await provider.load()
                received.append(result)
            }

            // Assertions.
            #expect(
                received.count == resolvedExpected.count,
                "[\(tc.description)] expected \(resolvedExpected.count) results, got \(received.count)"
            )

            for (idx, (got, want)) in zip(received, resolvedExpected).enumerated() {
                switch (got, want) {
                case (.success(let gotCfg), .success(configJSON: let wantJSON)):
                    let wantCfg = try JSONDecoder().decode(
                        OPA.Config.self, from: Data(wantJSON.utf8))
                    #expect(
                        gotCfg == wantCfg,
                        "[\(tc.description)] result #\(idx) config mismatch")
                case (.failure, .failure):
                    break
                case (.success, .failure):
                    Issue.record("[\(tc.description)] result #\(idx) expected failure, got success")
                case (.failure(let e), .success):
                    Issue.record(
                        "[\(tc.description)] result #\(idx) expected success, got failure: \(e)")
                }
            }
        }

        @Test("isLongPollingEnabled defaults to false for non-HTTP loaders")
        func longPollingDefaultsFalse() async throws {
            let mockID = MockBundleLoaderRegistry.shared.register(scripted: [])
            defer { MockBundleLoaderRegistry.shared.unregister(id: mockID) }

            let bootConfigJSON = Self.bootConfigTemplate.replacingOccurrences(
                of: "__MOCK_ID__", with: mockID)
            let bootConfig = try JSONDecoder().decode(
                OPA.Config.self, from: Data(bootConfigJSON.utf8))

            let provider = try OPA.DiscoveryConfigProvider(
                bootConfig: bootConfig,
                bundleLoaders: [OPA.MockBundleLoader.self]
            )

            #expect(provider.isLongPollingEnabled() == false)
        }
    }

    // MARK: - Plan Injection / Validation Tests

    /// Covers the three ways a discovery bundle can interact with the
    /// configured `discovery.decision` entrypoint:
    ///   (a) plan present + name matches -> bundle used as-is
    ///   (b) plan present + name does not match -> load() fails with a
    ///       descriptive error rather than silently overriding the bundle
    ///   (c) no plan present -> a ``MiniPlanner``-generated fallback plan
    ///       is injected so data-only bundles resolve against their data tree
    @Suite("PlanInjection")
    struct PlanInjectionTests {

        init() {
            TestLogging.ensureBootstrapped()
        }

        /// Builds a plan-less discovery bundle whose data tree contains the
        /// intended OPA.Config at the path specified by `discovery.config`.
        /// This is intended for testing the MiniPlanner's data query plans.
        static func makeDataOnlyDiscoveryBundle(configJSON: String) throws -> OPA.Bundle {
            let configValue = try JSONDecoder().decode(AST.RegoValue.self, from: Data(configJSON.utf8))
            let nested: AST.RegoValue = .object([
                .string("discovery"): .object([.string("config"): configValue])
            ])
            let manifest = OPA.Manifest(revision: UUID().uuidString, roots: ["discovery/config"])
            return try OPA.Bundle(
                manifest: manifest,
                planFiles: [],
                regoFiles: [],
                data: nested
            )
        }

        /// Decodes the LoadTests boot-config template with a given mock ID.
        static func makeBootConfig(mockID: String) throws -> OPA.Config {
            let json = LoadTests.bootConfigTemplate.replacingOccurrences(
                of: "__MOCK_ID__", with: mockID)
            return try JSONDecoder().decode(OPA.Config.self, from: Data(json.utf8))
        }

        @Test("Plan present + decision matches plan name -> load succeeds")
        func planPresentMatchSucceeds() async throws {
            // decisionPath (plan name) matches the boot config's
            // `discovery.decision` ("discovery/config").
            let bundle = try makeDiscoveryBundle(
                decisionPath: "discovery/config",
                configDataPath: "my/discovery/data/path",
                configJSON: """
                    { "labels": { "env": "prod" } }
                    """
            )

            let mockID = MockBundleLoaderRegistry.shared.register(scripted: [.success(bundle)])
            defer { MockBundleLoaderRegistry.shared.unregister(id: mockID) }

            var provider = try OPA.DiscoveryConfigProvider(
                bootConfig: try Self.makeBootConfig(mockID: mockID),
                bundleLoaders: [OPA.MockBundleLoader.self]
            )

            let result = await provider.load()
            guard case .success(let merged) = result else {
                Issue.record("Expected success, got \(result)")
                return
            }
            #expect(merged.labels["env"] == "prod")
        }

        @Test("Plan present + decision does not match plan name -> load fails")
        func planPresentMismatchErrors() async throws {
            // Plan name is `different/path`, but boot config's decision is
            // `discovery/config`. The provider should refuse to silently
            // inject a fallback plan.
            let bundle = try makeDiscoveryBundle(
                decisionPath: "different/path",
                configDataPath: "some/data/path",
                configJSON: """
                    { "labels": { "env": "prod" } }
                    """
            )

            let mockID = MockBundleLoaderRegistry.shared.register(scripted: [.success(bundle)])
            defer { MockBundleLoaderRegistry.shared.unregister(id: mockID) }

            var provider = try OPA.DiscoveryConfigProvider(
                bootConfig: try Self.makeBootConfig(mockID: mockID),
                bundleLoaders: [OPA.MockBundleLoader.self]
            )

            let result = await provider.load()
            guard case .failure(let error) = result else {
                Issue.record("Expected failure, got \(result)")
                return
            }
            // The error message should name both the bundle's plan and the
            // expected entrypoint so the operator can diagnose easily.
            let msg = String(describing: error)
            #expect(msg.contains("different/path"), "error should name the bundle's plan: \(msg)")
            #expect(msg.contains("discovery/config"), "error should name the expected entrypoint: \(msg)")
        }

        @Test("Plan missing -> MiniPlanner fallback resolves data-only bundle")
        func planMissingInjectsMiniPlanner() async throws {
            let bundle = try Self.makeDataOnlyDiscoveryBundle(
                configJSON: """
                    { "labels": { "env": "staging" } }
                    """
            )

            let mockID = MockBundleLoaderRegistry.shared.register(scripted: [.success(bundle)])
            defer { MockBundleLoaderRegistry.shared.unregister(id: mockID) }

            var provider = try OPA.DiscoveryConfigProvider(
                bootConfig: try Self.makeBootConfig(mockID: mockID),
                bundleLoaders: [OPA.MockBundleLoader.self]
            )

            let result = await provider.load()
            guard case .success(let merged) = result else {
                Issue.record("Expected success, got \(result)")
                return
            }
            #expect(merged.labels["env"] == "staging")
        }
    }
}
