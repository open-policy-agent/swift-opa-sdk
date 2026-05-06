import Crypto
import Foundation
import Rego
import SwiftASN1
import Testing
import X509

@testable import Runtime

// MARK: - OAuth2 Client Credentials HTTP Bundle Tests

@Suite("RuntimeHTTPBundleOAuth2Tests")
struct RuntimeHTTPBundleOAuth2Tests {

    // MARK: - Invalid (decode-time) cases

    struct InvalidTestCase: Sendable {
        let description: String
        let configJSON: String
    }

    static var invalidTestCases: [InvalidTestCase] {
        [
            InvalidTestCase(
                description: "missing token_url",
                configJSON: """
                    {
                      "services": {
                        "test-svc": {
                          "url": "https://example.com",
                          "credentials": {
                            "oauth2": {
                              "client_id": "id",
                              "client_secret": "secret"
                            }
                          }
                        }
                      },
                      "bundles": {
                        "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
                      }
                    }
                    """
            ),
            InvalidTestCase(
                description: "token_url not https",
                configJSON: """
                    {
                      "services": {
                        "test-svc": {
                          "url": "https://example.com",
                          "credentials": {
                            "oauth2": {
                              "token_url": "http://example.com/token",
                              "client_id": "id",
                              "client_secret": "secret"
                            }
                          }
                        }
                      },
                      "bundles": {
                        "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
                      }
                    }
                    """
            ),
            InvalidTestCase(
                description: "unsupported grant_type=jwt_bearer",
                configJSON: """
                    {
                      "services": {
                        "test-svc": {
                          "url": "https://example.com",
                          "credentials": {
                            "oauth2": {
                              "token_url": "https://example.com/token",
                              "client_id": "id",
                              "client_secret": "secret",
                              "grant_type": "jwt_bearer"
                            }
                          }
                        }
                      },
                      "bundles": {
                        "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
                      }
                    }
                    """
            ),
        ]
    }

    @Test(arguments: invalidTestCases)
    func testInvalidDecode(tc: InvalidTestCase) async throws {
        #expect(throws: (any Error).self) {
            _ = try JSONDecoder().decode(OPA.Config.self, from: tc.configJSON.data(using: .utf8)!)
        }
    }

    // MARK: - Happy path

    @Test("OAuth2 client credentials: happy path fetches token then bundle")
    func testHappyPath() async throws {
        let servers = try await startOAuth2TestServers(tokenResponseExpiresIn: 3600)
        defer { servers.shutdown() }

        let configJSON = oauth2ConfigJSON(servers: servers, extra: "")
        let config = try JSONDecoder().decode(OPA.Config.self, from: configJSON.data(using: .utf8)!)
        let rt = try OPA.Runtime(config: config)

        let backgroundFetchTask = Task { try await rt.run() }
        defer { backgroundFetchTask.cancel() }

        let _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(5))
        let bundleStorage = await rt.bundleStorage
        let bundleResult = try #require(bundleStorage["test"], "Expected bundle 'test' to be present")
        let _ = try requireBundleLoadSuccess(bundleResult, context: "happy-path OAuth2 bundle load")

        let tokenRequests = servers.token.state.requests.filter { $0.uri.hasPrefix(servers.tokenPath) }
        let bundleRequests = servers.bundle.state.requests.filter { $0.uri == "/bundles/bundle.tar.gz" }
        #expect(tokenRequests.count >= 1, "Expected at least one token request")
        #expect(bundleRequests.count >= 1, "Expected at least one bundle request")

        // Token endpoint was hit with Basic auth over a form-encoded POST.
        let tokenReq = try #require(tokenRequests.first)
        #expect(tokenReq.method == "POST")
        #expect(
            tokenReq.headerValue(for: "content-type") == "application/x-www-form-urlencoded"
        )
        let expectedBasic = "Basic " + Data("id:secret".utf8).base64EncodedString()
        #expect(tokenReq.headerValue(for: "authorization") == expectedBasic)

        // Bundle request carried the bearer token issued by the token endpoint.
        let bundleReq = try #require(bundleRequests.first)
        #expect(bundleReq.method == "GET")
        #expect(
            bundleReq.headerValue(for: "authorization") == "Bearer test-access-token"
        )
    }

    // MARK: - Token reuse (cache hit)

    @Test("OAuth2 client credentials: cached token is reused across load() calls")
    func testTokenCacheReuse() async throws {
        let servers = try await startOAuth2TestServers(tokenResponseExpiresIn: 3600)
        defer { servers.shutdown() }

        let configJSON = oauth2ConfigJSON(servers: servers, extra: "")
        var loader = try makeRESTClientBundleLoader(configJSON: configJSON)

        let _ = try requireBundleLoadSuccess(await loader.load(), context: "first load")
        let _ = try requireBundleLoadSuccess(await loader.load(), context: "second load")
        let _ = try requireBundleLoadSuccess(await loader.load(), context: "third load")

        let tokenRequests = servers.token.state.requests.filter { $0.uri.hasPrefix(servers.tokenPath) }
        #expect(
            tokenRequests.count == 1,
            "Expected exactly 1 token request (cache hits on loads 2 and 3), got \(tokenRequests.count)"
        )
    }

    // MARK: - Near-expiry re-fetch

    @Test("OAuth2 client credentials: token is re-fetched when within refresh leeway")
    func testNearExpiryRefetch() async throws {
        // `expires_in = 5` is below the 10s leeway — every load should
        // consider the cache stale and request a new token.
        let servers = try await startOAuth2TestServers(tokenResponseExpiresIn: 5)
        defer { servers.shutdown() }

        let configJSON = oauth2ConfigJSON(servers: servers, extra: "")
        var loader = try makeRESTClientBundleLoader(configJSON: configJSON)

        let _ = try requireBundleLoadSuccess(await loader.load(), context: "first load")
        let _ = try requireBundleLoadSuccess(await loader.load(), context: "second load")

        let tokenRequests = servers.token.state.requests.filter { $0.uri.hasPrefix(servers.tokenPath) }
        #expect(
            tokenRequests.count == 2,
            "Expected 2 token requests (no leeway reuse), got \(tokenRequests.count)"
        )
    }

    // MARK: - Token endpoint failure

    @Test("OAuth2 client credentials: bundle load fails when token endpoint returns 401")
    func testTokenEndpointFailure() async throws {
        let env = try makeOAuth2Env()
        defer { env.cleanup() }
        let tokenPath = "/oauth2/token"

        let tokenServer = try await TestBundleServer.start(
            paths: [
                tokenPath: PathState(
                    data: Data(),
                    etag: nil,
                    forceStatusCode: 401,
                    contentType: "application/json"
                )
            ],
            tls: TestBundleServerTLSOptions(
                serverCertPath: env.serverCert,
                serverKeyPath: env.serverKey,
                clientCACertPath: nil
            )
        )
        defer { Task { try? await tokenServer.shutdown() } }

        let bundle = try makeExampleBundle()
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: bundle)
        let bundleServer = try await TestBundleServer.start(
            files: ["/bundles/bundle.tar.gz": bundleData])
        defer { Task { try? await bundleServer.shutdown() } }

        let configJSON = oauth2ConfigJSON(
            bundleBaseURL: bundleServer.baseURL,
            tokenURL: "\(tokenServer.baseURL)\(tokenPath)",
            extra: "")
        var loader = try makeRESTClientBundleLoader(configJSON: configJSON)

        let result = await loader.load()
        let _ = try requireBundleLoadFailure(result, context: "401 from token endpoint")

        // The bundle request must not have been attempted.
        let bundleRequests = bundleServer.state.requests.filter { $0.uri == "/bundles/bundle.tar.gz" }
        #expect(
            bundleRequests.isEmpty,
            "Bundle request should not be attempted when token fetch fails"
        )
    }

    // MARK: - Non-bearer token_type

    @Test("OAuth2 client credentials: bundle load fails when token endpoint returns non-bearer token_type")
    func testNonBearerTokenType() async throws {
        let env = try makeOAuth2Env()
        defer { env.cleanup() }
        let tokenPath = "/oauth2/token"

        let macTokenJSON = Data(
            #"{"access_token":"tok","token_type":"Mac","expires_in":3600}"#.utf8)

        let tokenServer = try await TestBundleServer.start(
            paths: [
                tokenPath: PathState(
                    data: macTokenJSON,
                    etag: nil,
                    contentType: "application/json"
                )
            ],
            tls: TestBundleServerTLSOptions(
                serverCertPath: env.serverCert,
                serverKeyPath: env.serverKey,
                clientCACertPath: nil
            )
        )
        defer { Task { try? await tokenServer.shutdown() } }

        let bundle = try makeExampleBundle()
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: bundle)
        let bundleServer = try await TestBundleServer.start(
            files: ["/bundles/bundle.tar.gz": bundleData])
        defer { Task { try? await bundleServer.shutdown() } }

        let configJSON = oauth2ConfigJSON(
            bundleBaseURL: bundleServer.baseURL,
            tokenURL: "\(tokenServer.baseURL)\(tokenPath)",
            extra: "")
        var loader = try makeRESTClientBundleLoader(configJSON: configJSON)

        let result = await loader.load()
        let _ = try requireBundleLoadFailure(result, context: "Mac token_type not supported")

        let bundleRequests = bundleServer.state.requests.filter { $0.uri == "/bundles/bundle.tar.gz" }
        #expect(bundleRequests.isEmpty, "No bundle request should be made with a bad token_type")
    }
}

// MARK: - Type Extensions

extension RuntimeHTTPBundleOAuth2Tests.InvalidTestCase: CustomTestStringConvertible {
    var testDescription: String { description }
}

// MARK: - OAuth2 Test Environment

/// Temp-dir + self-signed server cert used by the OAuth2 token-endpoint
/// test server. The OAuth2 loader enforces `https://` for `token_url`,
/// so we need a TLS-capable test server for the token endpoint; the
/// bundle endpoint can stay plain HTTP.
struct OAuth2TestEnv {
    let tmpDir: URL
    let serverCert: String
    let serverKey: String

    func cleanup() {
        try? FileManager.default.removeItem(at: tmpDir)
    }
}

/// Generates a self-signed server cert with a `127.0.0.1` SAN.
func makeOAuth2Env() throws -> OAuth2TestEnv {
    let tmpDir = try makeTempDir()
    let serverCert = tmpDir.appendingPathComponent("server.crt").path
    let serverKey = tmpDir.appendingPathComponent("server.key").path
    try generateTestCertificate(
        certPath: serverCert,
        keyPath: serverKey,
        serialNumber: 1,
        subjectAltNames: [sanIPv4("127.0.0.1")]
    )
    return OAuth2TestEnv(tmpDir: tmpDir, serverCert: serverCert, serverKey: serverKey)
}

/// Pair of test servers used by the happy-path OAuth2 tests: an HTTPS
/// server for the token endpoint (OAuth2 requires https) and a plain
/// HTTP server for the bundle endpoint.
struct OAuth2TestServers {
    let token: TestBundleServer
    let bundle: TestBundleServer
    let tokenPath: String
    let env: OAuth2TestEnv

    func shutdown() {
        env.cleanup()
        Task { try? await token.shutdown() }
        Task { try? await bundle.shutdown() }
    }
}

/// Starts a TLS-enabled token server returning a standard JSON token
/// response, alongside an HTTP server serving the bundle.
func startOAuth2TestServers(
    tokenResponseExpiresIn: Int64 = 3600,
    accessToken: String = "test-access-token"
) async throws -> OAuth2TestServers {
    let env = try makeOAuth2Env()
    let tokenPath = "/oauth2/token"

    let tokenJSON = Data(
        #"{"access_token":"\#(accessToken)","token_type":"Bearer","expires_in":\#(tokenResponseExpiresIn)}"#
            .utf8)

    let tokenServer = try await TestBundleServer.start(
        paths: [
            tokenPath: PathState(
                data: tokenJSON,
                etag: nil,
                contentType: "application/json"
            )
        ],
        tls: TestBundleServerTLSOptions(
            serverCertPath: env.serverCert,
            serverKeyPath: env.serverKey,
            clientCACertPath: nil
        )
    )

    let bundle = try makeExampleBundle()
    let bundleData = try OPA.Bundle.encodeToTarball(bundle: bundle)
    let bundleServer = try await TestBundleServer.start(
        files: ["/bundles/bundle.tar.gz": bundleData])

    return OAuth2TestServers(
        token: tokenServer,
        bundle: bundleServer,
        tokenPath: tokenPath,
        env: env)
}

/// Builds an OPA config JSON for the common case: single service with a
/// plain-HTTP bundle endpoint plus an HTTPS OAuth2 token endpoint.
/// `allow_insecure_tls: true` tells the OAuth2 loader to skip cert
/// verification on the token request (the server is self-signed).
func oauth2ConfigJSON(servers: OAuth2TestServers, extra: String) -> String {
    return oauth2ConfigJSON(
        bundleBaseURL: servers.bundle.baseURL,
        tokenURL: "\(servers.token.baseURL)\(servers.tokenPath)",
        extra: extra)
}

func oauth2ConfigJSON(
    bundleBaseURL: String,
    tokenURL: String,
    extra: String
) -> String {
    return """
        {
          "services": {
            "test-svc": {
              "url": "\(bundleBaseURL)",
              "allow_insecure_tls": true,
              "credentials": {
                "oauth2": {
                  "token_url": "\(tokenURL)",
                  "client_id": "id",
                  "client_secret": "secret"\(extra)
                }
              }
            }
          },
          "bundles": {
            "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
          }
        }
        """
}
