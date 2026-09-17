import Foundation
import Rego
import Testing

@testable import Runtime

// MARK: - Bearer Auth HTTP Bundle Tests

@Suite("RuntimeHTTPBundleBearerAuthTests")
struct RuntimeHTTPBundleBearerAuthTests {

    // MARK: - Valid Cases

    struct ValidTestCase: Sendable {
        let description: String
        let credentialsJSON: String
        let needsTokenFile: Bool

        init(description: String, credentialsJSON: String, needsTokenFile: Bool = false) {
            self.description = description
            self.credentialsJSON = credentialsJSON
            self.needsTokenFile = needsTokenFile
        }
    }

    static var validTestCases: [ValidTestCase] {
        [
            ValidTestCase(
                description: "bearer token inline",
                credentialsJSON: #"""
                    "credentials": {
                      "bearer": {
                        "token": "my-secret-token"
                      }
                    }
                    """#
            ),
            ValidTestCase(
                description: "bearer token_path",
                credentialsJSON: #"""
                    "credentials": {
                      "bearer": {
                        "token_path": "{TOKEN_PATH}"
                      }
                    }
                    """#,
                needsTokenFile: true
            ),
            ValidTestCase(
                description: "bearer token with custom scheme",
                credentialsJSON: #"""
                    "credentials": {
                      "bearer": {
                        "token": "custom-scheme-token",
                        "scheme": "Token"
                      }
                    }
                    """#
            ),
        ]
    }

    @Test(arguments: validTestCases)
    func testValid(tc: ValidTestCase) async throws {
        let testBundle = try makeExampleBundle()
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: testBundle)

        let server = try await TestBundleServer.start(files: [
            "/bundles/bundle.tar.gz": bundleData
        ])
        defer { Task { try? await server.shutdown() } }

        var credentials = tc.credentialsJSON
        var tokenFile: URL? = nil

        if tc.needsTokenFile {
            let tmpDir = FileManager.default.temporaryDirectory
            let tf = tmpDir.appendingPathComponent("opa-test-bearer-token-\(UUID().uuidString).txt")
            try "file-based-secret-token".write(to: tf, atomically: true, encoding: .utf8)
            tokenFile = tf
            credentials = credentials.replacingOccurrences(of: "{TOKEN_PATH}", with: tf.path)
        }
        defer { if let tokenFile { try? FileManager.default.removeItem(at: tokenFile) } }
        let configJSON = """
            {
              "services": {
                "test-svc": {
                  "url": "\(server.baseURL)",
                  \(credentials)
                }
              },
              "bundles": {
                "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
              }
            }
            """
        let config = try JSONDecoder().decode(OPA.Config.self, from: configJSON.data(using: .utf8)!)
        let rt = try OPA.Runtime(config: config)

        let backgroundFetchTask = Task { try await rt.run() }
        defer { backgroundFetchTask.cancel() }

        let _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(1))
        let bundleStorage = rt.activeBundles()
        let bundleResult = try #require(
            bundleStorage.first, "Expected exactly 1 bundle, got \(bundleStorage.count)")
        #expect(bundleStorage.count == 1, "Expected exactly 1 bundle, got \(bundleStorage.count)")
        guard bundleResult.value.bundle != nil else {
            Issue.record("Expected bundle '\(bundleResult.key)' to be loaded, got \(bundleResult.value)")
            return
        }

        let dr = try await rt.decision("data/foo/hello", input: nil)
        #expect(dr.result.first == ["result": 1])
    }

    // MARK: - Invalid Cases

    struct InvalidTestCase: Sendable {
        let description: String
        let configJSON: String
        let failsAt: FailureStage

        enum FailureStage: Sendable {
            case decode
        }
    }

    static var invalidTestCases: [InvalidTestCase] {
        [
            InvalidTestCase(
                description: "both token and token_path specified",
                configJSON: """
                    {
                      "services": {
                          "test-svc": {
                            "url": "https://example.com",
                            "credentials": {
                              "bearer": {
                                "token": "inline-token",
                                "token_path": "/some/path/token.txt"
                              }
                            }
                          }
                      },
                      "bundles": {
                        "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
                      }
                    }
                    """,
                failsAt: .decode
            ),
            InvalidTestCase(
                description: "neither token nor token_path specified",
                configJSON: """
                    {
                      "services": {
                        "test-svc": {
                          "url": "https://example.com",
                          "credentials": {
                            "bearer": {}
                          }
                        }
                      },
                      "bundles": {
                        "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
                      }
                    }
                    """,
                failsAt: .decode
            ),
            InvalidTestCase(
                description: "empty token string",
                configJSON: """
                    {
                      "services": {
                        "test-svc": {
                          "url": "https://example.com",
                          "credentials": {
                            "bearer": {
                              "token": ""
                            }
                          }
                        }
                      },
                      "bundles": {
                        "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
                      }
                    }
                    """,
                failsAt: .decode
            ),
        ]
    }

    @Test(arguments: invalidTestCases)
    func testInvalid(tc: InvalidTestCase) async throws {
        switch tc.failsAt {
        case .decode:
            #expect(throws: (any Error).self) {
                _ = try JSONDecoder().decode(OPA.Config.self, from: tc.configJSON.data(using: .utf8)!)
            }
        }
    }
}

// MARK: - Type Extensions

extension RuntimeHTTPBundleBearerAuthTests.ValidTestCase: CustomTestStringConvertible {
    var testDescription: String { description }
}

extension RuntimeHTTPBundleBearerAuthTests.InvalidTestCase: CustomTestStringConvertible {
    var testDescription: String { description }
}
