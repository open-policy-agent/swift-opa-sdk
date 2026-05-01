import Crypto
import Foundation
import Rego
import SwiftASN1
import Testing
import X509

@testable import Runtime

// MARK: - Client TLS Auth HTTP Bundle Tests

@Suite("RuntimeHTTPBundleClientTLSAuthTests")
struct RuntimeHTTPBundleClientTLSAuthTests {

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
                description: "missing cert field",
                configJSON: """
                    {
                      "services": {
                        "test-svc": {
                          "url": "https://example.com",
                          "credentials": {
                            "client_tls": {
                              "private_key": "/etc/opa/key.pem"
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
                description: "missing private_key field",
                configJSON: """
                    {
                      "services": {
                        "test-svc": {
                          "url": "https://example.com",
                          "credentials": {
                            "client_tls": {
                              "cert": "/etc/opa/cert.pem"
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
                description: "empty cert string",
                configJSON: """
                    {
                      "services": {
                        "test-svc": {
                          "url": "https://example.com",
                          "credentials": {
                            "client_tls": {
                              "cert": "",
                              "private_key": "/etc/opa/key.pem"
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
                description: "empty private_key string",
                configJSON: """
                    {
                      "services": {
                        "test-svc": {
                          "url": "https://example.com",
                          "credentials": {
                            "client_tls": {
                              "cert": "/etc/opa/cert.pem",
                              "private_key": ""
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
                description: "deprecated credentials.client_tls.ca_cert and tls.ca_cert both set",
                configJSON: """
                    {
                      "services": {
                        "test-svc": {
                          "url": "https://example.com",
                          "tls": {"ca_cert": "/etc/opa/server-ca.pem"},
                          "credentials": {
                            "client_tls": {
                              "cert": "/etc/opa/cert.pem",
                              "private_key": "/etc/opa/key.pem",
                              "ca_cert": "/etc/opa/legacy-ca.pem"
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

    // MARK: - Client TLS Failure Test

    @Test("client TLS fails visibly when the client cert is not trusted by the server")
    func testUntrustedClientCert() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        // Generate a second, independent client cert that the server has no
        // knowledge of. The server is configured to trust only `env.clientCert`
        // (via `startMTLSServer`), so presenting `rogueCert` should cause the
        // server to reject the handshake with a TLS alert.
        let rogueCert = env.tmpDir.appendingPathComponent("rogue-client.crt").path
        let rogueKey = env.tmpDir.appendingPathComponent("rogue-client.key").path
        try generateTestCertificate(
            certPath: rogueCert,
            keyPath: rogueKey,
            serialNumber: 42
        )

        let server = try await startMTLSServer(env: env)
        defer { Task { try? await server.shutdown() } }

        let configJSON = """
            {
              "services": {
                "test-svc": {
                  "url": "\(server.baseURL)",
                  "tls": {"ca_cert": "\(env.serverCert)"},
                  "credentials": {
                    "client_tls": {
                      "cert": "\(rogueCert)",
                      "private_key": "\(rogueKey)"
                    }
                  }
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

        // The rogue client cert will fail the server's client-cert validation
        // and the handshake will be aborted with a TLS alert. That surfaces
        // through `bundleStorage` as a `.failure(...)`.
        let failed = await waitForBundleLoad(
            rt: rt, name: "test", timeout: .seconds(10)
        ) { result in
            if case .failure = result { return true }
            return false
        }
        guard let result = failed else {
            Issue.record("Test bundle failed to load")
            return
        }
        let _ = try requireBundleLoadFailure(result, context: "server should reject the untrusted client cert")
    }

    // MARK: - Runtime-Time Error Cases (no mTLS server required)

    @Test("bundle load fails when client cert file does not exist on disk")
    func testMissingCertFile() async throws {
        // Plain HTTP server is fine here — the failure happens during
        // HTTPClient.Configuration construction (loadCertificate) before
        // we even attempt to talk to the bundle server.
        let server = try await TestBundleServer.start(files: [:])
        defer { Task { try? await server.shutdown() } }

        let missingCert = "/tmp/nonexistent-cert-\(UUID().uuidString).pem"
        let missingKey = "/tmp/nonexistent-key-\(UUID().uuidString).pem"

        let configJSON = """
            {
              "services": {
                "test-svc": {
                  "url": "\(server.baseURL)",
                  "credentials": {
                    "client_tls": {
                      "cert": "\(missingCert)",
                      "private_key": "\(missingKey)"
                    }
                  }
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

        let _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(2))
        let bundleStorage = await rt.bundleStorage
        let bundleResult = try #require(
            bundleStorage["test"], "Expected bundle storage entry for 'test'")
        let _ = try requireBundleLoadFailure(bundleResult, context: "cert file missing")
    }

    @Test("bundle load fails when client cert path exists but private_key path does not")
    func testMissingPrivateKeyFile() async throws {
        let server = try await TestBundleServer.start(files: [:])
        defer { Task { try? await server.shutdown() } }

        // Generate a valid cert file but reference a missing private_key path.
        let tmpDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tmpDir) }
        let certPath = tmpDir.appendingPathComponent("client.crt").path
        let keyPath = tmpDir.appendingPathComponent("client.key").path
        try generateTestCertificate(certPath: certPath, keyPath: keyPath, serialNumber: 1)

        // Now point at a non-existent key path.
        let bogusKey = tmpDir.appendingPathComponent("does-not-exist.key").path

        let configJSON = """
            {
              "services": {
                "test-svc": {
                  "url": "\(server.baseURL)",
                  "credentials": {
                    "client_tls": {
                      "cert": "\(certPath)",
                      "private_key": "\(bogusKey)"
                    }
                  }
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

        let _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(2))
        let bundleStorage = await rt.bundleStorage
        let bundleResult = try #require(bundleStorage["test"])
        let _ = try requireBundleLoadFailure(bundleResult, context: "key file missing")
    }

    // MARK: - Valid Cases (require mTLS test server)

    @Test("client TLS happy path: server validates client cert; client validates server via tls.ca_cert")
    func testClientTLSHappyPath() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        let server = try await startMTLSServer(env: env)
        defer { Task { try? await server.shutdown() } }

        let configJSON = """
            {
              "services": {
                "test-svc": {
                  "url": "\(server.baseURL)",
                  "tls": {"ca_cert": "\(env.serverCert)"},
                  "credentials": {
                    "client_tls": {
                      "cert": "\(env.clientCert)",
                      "private_key": "\(env.clientKey)"
                    }
                  }
                }
              },
              "bundles": {
                "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
              }
            }
            """
        try await runHappyPath(configJSON: configJSON)
    }

    @Test("client TLS with allow_insecure_tls = true bypasses server cert verification")
    func testAllowInsecureTLS() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        let server = try await startMTLSServer(env: env)
        defer { Task { try? await server.shutdown() } }

        // No tls.ca_cert configured. Server cert is self-signed and would
        // normally fail validation; allow_insecure_tls = true skips that.
        let configJSON = """
            {
              "services": {
                "test-svc": {
                  "url": "\(server.baseURL)",
                  "allow_insecure_tls": true,
                  "credentials": {
                    "client_tls": {
                      "cert": "\(env.clientCert)",
                      "private_key": "\(env.clientKey)"
                    }
                  }
                }
              },
              "bundles": {
                "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
              }
            }
            """
        try await runHappyPath(configJSON: configJSON)
    }

    @Test("client TLS with deprecated credentials.client_tls.ca_cert (no services[_].tls block)")
    func testDeprecatedClientTLSCACert() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        let server = try await startMTLSServer(env: env)
        defer { Task { try? await server.shutdown() } }

        // Uses the legacy `credentials.client_tls.ca_cert` field (with NO
        // services[_].tls block) to point at the server's CA cert.
        let configJSON = """
            {
              "services": {
                "test-svc": {
                  "url": "\(server.baseURL)",
                  "credentials": {
                    "client_tls": {
                      "cert": "\(env.clientCert)",
                      "private_key": "\(env.clientKey)",
                      "ca_cert": "\(env.serverCert)"
                    }
                  }
                }
              },
              "bundles": {
                "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
              }
            }
            """
        try await runHappyPath(configJSON: configJSON)
    }

    @Test("client TLS with system_ca_required = true + extra ca_cert appends to system roots")
    func testSystemCARequiredWithExtraCA() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        let server = try await startMTLSServer(env: env)
        defer { Task { try? await server.shutdown() } }

        // The server cert is self-signed and not in the system trust store.
        // With system_ca_required = true AND ca_cert = serverCert, the user CA
        // must be layered on top of system roots via NIOSSL's
        // `additionalTrustRoots`. If our wiring were still the old "replace,
        // not append" stub, this would fail.
        let configJSON = """
            {
              "services": {
                "test-svc": {
                  "url": "\(server.baseURL)",
                  "tls": {
                    "ca_cert": "\(env.serverCert)",
                    "system_ca_required": true
                  },
                  "credentials": {
                    "client_tls": {
                      "cert": "\(env.clientCert)",
                      "private_key": "\(env.clientKey)"
                    }
                  }
                }
              },
              "bundles": {
                "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
              }
            }
            """
        try await runHappyPath(configJSON: configJSON)
    }

    @Test("client cert rotation: replacing the on-disk cert is picked up on the next load")
    func testClientCertRotation() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        // Server only trusts the original `env.clientCert`. We'll later
        // overwrite the client cert on disk with a brand-new self-signed cert
        // the server does NOT trust, and verify the next load fails — which
        // proves the loader re-read the cert files rather than caching.
        let server = try await startMTLSServer(env: env)
        defer { Task { try? await server.shutdown() } }

        // Short polling so the rotation gets picked up quickly.
        let configJSON = """
            {
              "services": {
                "test-svc": {
                  "url": "\(server.baseURL)",
                  "tls": {"ca_cert": "\(env.serverCert)"},
                  "credentials": {
                    "client_tls": {
                      "cert": "\(env.clientCert)",
                      "private_key": "\(env.clientKey)"
                    }
                  }
                }
              },
              "bundles": {
                "test": {
                  "service": "test-svc",
                  "resource": "/bundles/bundle.tar.gz",
                  "polling": {"min_delay_seconds": 1, "max_delay_seconds": 1}
                }
              }
            }
            """
        let config = try JSONDecoder().decode(OPA.Config.self, from: configJSON.data(using: .utf8)!)
        let rt = try OPA.Runtime(config: config)

        let backgroundFetchTask = Task { try await rt.run() }
        defer { backgroundFetchTask.cancel() }

        // Wait for first successful load.
        let _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(5))
        let firstStorage = await rt.bundleStorage
        guard case .success = firstStorage["test"] else {
            Issue.record(
                "Expected initial load to succeed, got \(String(describing: firstStorage["test"]))")
            return
        }

        // Rotate: overwrite the client cert on disk with a brand-new self-signed
        // cert. The server still only trusts the original cert, so the next load
        // must fail.
        try generateTestCertificate(
            certPath: env.clientCert,
            keyPath: env.clientKey,
            serialNumber: 99
        )

        // Poll for the storage entry to flip from .success to .failure.
        let flipped = await waitForBundleLoad(
            rt: rt, name: "test", timeout: .seconds(10)
        ) { result in
            if case .failure = result { return true }
            return false
        }
        guard let result = flipped else {
            Issue.record("Test bundle failed to load after cert rotation")
            return
        }
        let _ = try requireBundleLoadFailure(result, context: "expected transition to .failure after cert rotation")
    }

    // MARK: - Encrypted-PEM Happy Path
    //
    // swift-crypto's `pemRepresentation` only emits *unencrypted* PEM and there's
    // no Swift-native API to encrypt it with a passphrase.
    //
    // To cover that passphrase decrytion path without checking in hand-crafted
    // fixtures, we shell out to `openssl` at test time. This adds a build-env
    // dependency, so the test is gated on `SWIFT_OPA_OPENSSL_TESTS=1`.

    @Test(
        "client TLS happy path with encrypted (passphrase-protected) private key",
        .enabled(if: opensslTestsEnabled())
    )
    func testClientTLSEncryptedPrivateKey() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        // Encrypt the unencrypted client key in place with a passphrase.
        let passphrase = "swift-opa-test-passphrase"
        let encryptedKeyPath = env.tmpDir.appendingPathComponent("client-encrypted.key").path
        try encryptPEMPrivateKey(
            inputPath: env.clientKey,
            outputPath: encryptedKeyPath,
            passphrase: passphrase
        )

        let server = try await startMTLSServer(env: env)
        defer { Task { try? await server.shutdown() } }

        let configJSON = """
            {
              "services": {
                "test-svc": {
                  "url": "\(server.baseURL)",
                  "tls": {"ca_cert": "\(env.serverCert)"},
                  "credentials": {
                    "client_tls": {
                      "cert": "\(env.clientCert)",
                      "private_key": "\(encryptedKeyPath)",
                      "private_key_passphrase": "\(passphrase)"
                    }
                  }
                }
              },
              "bundles": {
                "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
              }
            }
            """
        try await runHappyPath(configJSON: configJSON)
    }

    // MARK: - Test-Local Helpers

    /// Runs the common happy-path pattern shared by several mTLS tests:
    /// decode the config, start a Runtime, wait for the bundle to load, and
    /// verify a decision evaluates against it.
    private func runHappyPath(configJSON: String) async throws {
        let config = try JSONDecoder().decode(OPA.Config.self, from: configJSON.data(using: .utf8)!)
        let rt = try OPA.Runtime(config: config)

        let backgroundFetchTask = Task { try await rt.run() }
        defer { backgroundFetchTask.cancel() }

        let _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(5))
        let bundleStorage = await rt.bundleStorage
        let bundleResult = try #require(bundleStorage["test"], "Expected bundle storage entry for 'test'")
        guard case .success = bundleResult else {
            Issue.record("Expected bundle 'test' to be .success, got \(bundleResult)")
            return
        }

        let dr = try await rt.decision("data/foo/hello", input: nil)
        #expect(dr.result.first == ["result": 1])
    }

    /// Convenience wrapper that bakes the default example bundle under
    /// `/bundles/bundle.tar.gz` and enables mTLS on the shared test server.
    private func startMTLSServer(env: ClientTLSEnv) async throws -> TestBundleServer {
        let bundle = try makeExampleBundle()
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: bundle)
        return try await TestBundleServer.start(
            files: ["/bundles/bundle.tar.gz": bundleData],
            tls: TestBundleServerTLSOptions(
                serverCertPath: env.serverCert,
                serverKeyPath: env.serverKey,
                clientCACertPath: env.clientCert
            )
        )
    }

}

// MARK: - Type Extensions

extension RuntimeHTTPBundleClientTLSAuthTests.InvalidTestCase: CustomTestStringConvertible {
    var testDescription: String { description }
}

// MARK: - Client TLS Test Environment

/// Bundle of temp filesystem paths + generated certs used by the happy-path
/// mTLS tests. Call `cleanup()` in a `defer` to remove the temp directory.
struct ClientTLSEnv {
    let tmpDir: URL
    let serverCert: String
    let serverKey: String
    let clientCert: String
    let clientKey: String

    func cleanup() {
        try? FileManager.default.removeItem(at: tmpDir)
    }
}

/// Sets up a fresh temp dir containing a server cert (with a `127.0.0.1` SAN
/// so clients doing hostname verification accept it) and a client cert. Both
/// carry `clientAuth` + `serverAuth` EKUs so either may appear on either side
/// of a TLS connection without EKU-based rejection.
func makeClientTLSEnv() throws -> ClientTLSEnv {
    let tmpDir = try makeTempDir()
    let serverCert = tmpDir.appendingPathComponent("server.crt").path
    let serverKey = tmpDir.appendingPathComponent("server.key").path
    let clientCert = tmpDir.appendingPathComponent("client.crt").path
    let clientKey = tmpDir.appendingPathComponent("client.key").path

    try generateTestCertificate(
        certPath: serverCert,
        keyPath: serverKey,
        serialNumber: 1,
        subjectAltNames: [sanIPv4("127.0.0.1")]
    )
    try generateTestCertificate(
        certPath: clientCert,
        keyPath: clientKey,
        serialNumber: 2
    )

    return ClientTLSEnv(
        tmpDir: tmpDir,
        serverCert: serverCert,
        serverKey: serverKey,
        clientCert: clientCert,
        clientKey: clientKey
    )
}

// MARK: - Cert Helpers

/// Generates a self-signed ECDSA P-256 certificate and writes it along with
/// its private key to the given paths in PEM format.
///
/// Defaults to both `clientAuth` and `serverAuth` EKUs so the same helper can
/// produce certs for either side of an mTLS test. Pass `subjectAltNames` to
/// make the cert usable as a server identity with hostname/IP verification.
func generateTestCertificate(
    certPath: String,
    keyPath: String,
    serialNumber: Int64,
    extendedKeyUsage: [ExtendedKeyUsage.Usage] = [.clientAuth, .serverAuth],
    subjectAltNames: [GeneralName] = []
) throws {
    let swiftCryptoKey = P256.Signing.PrivateKey()
    let key = Certificate.PrivateKey(swiftCryptoKey)

    let subject = try DistinguishedName {
        OrganizationName("Test Org")
        CommonName("Test Cert")
    }

    // Back-date `notBefore` by an hour to absorb any host clock skew between
    // cert issuance and the TLS handshake.
    let now = Date()
    let notBefore = now.addingTimeInterval(-60 * 60)
    let notAfter = now.addingTimeInterval(24 * 60 * 60)

    // These are self-signed test certs that double as their own trust anchor,
    // so they must declare `cA = true` in BasicConstraints and include
    // `keyCertSign` in KeyUsage. Otherwise BoringSSL will refuse to use them
    // as a trust root and the TLS handshake will fail with either
    // "UNKNOWN_CA" (server-side rejection) or a client-side abort during
    // server-cert validation.
    let extensions = try Certificate.Extensions {
        Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
        Critical(
            KeyUsage(
                digitalSignature: true,
                keyEncipherment: true,
                keyCertSign: true
            )
        )
        try ExtendedKeyUsage(extendedKeyUsage)
        if !subjectAltNames.isEmpty {
            SubjectAlternativeNames(subjectAltNames)
        }
    }

    let certificate = try Certificate(
        version: .v3,
        serialNumber: Certificate.SerialNumber(
            bytes: ArraySlice(withUnsafeBytes(of: serialNumber.bigEndian, Array.init))
        ),
        publicKey: key.publicKey,
        notValidBefore: notBefore,
        notValidAfter: notAfter,
        issuer: subject,
        subject: subject,
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: extensions,
        issuerPrivateKey: key
    )

    let certPEM = try certificate.serializeAsPEM().pemString
    try certPEM.write(toFile: certPath, atomically: true, encoding: .utf8)

    let keyPEM = swiftCryptoKey.pemRepresentation
    try keyPEM.write(toFile: keyPath, atomically: true, encoding: .utf8)
}

/// Build a `GeneralName` for an IPv4 dotted-quad address, suitable for use in
/// a `SubjectAlternativeNames` extension.
func sanIPv4(_ s: String) -> GeneralName {
    let bytes = s.split(separator: ".").compactMap { UInt8($0) }
    precondition(bytes.count == 4, "Invalid IPv4 address literal: \(s)")
    return .ipAddress(ASN1OctetString(contentBytes: ArraySlice(bytes)))
}

// MARK: - OpenSSL Test Helpers

/// Returns true when OpenSSL-dependent tests should run. Controlled via the
/// `SWIFT_OPA_OPENSSL_TESTS` env var (set to `1` to enable). The `Makefile`
/// auto-enables this when `openssl` is on `PATH`; CI does the same.
func opensslTestsEnabled() -> Bool {
    ProcessInfo.processInfo.environment["SWIFT_OPA_OPENSSL_TESTS"] == "1"
}

/// #ncrypts an unencrypted PEM-formatted private key by shelling out to
/// `openssl pkcs8 -topk8 -v2 aes-256-cbc`. Produces a standard encrypted
/// PKCS#8 PEM that NIOSSL can decrypt given the matching passphrase.
///
/// Only callable from tests guarded by `opensslTestsEnabled()`.
func encryptPEMPrivateKey(inputPath: String, outputPath: String, passphrase: String) throws {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    proc.arguments = [
        "openssl", "pkcs8",
        "-topk8",
        "-in", inputPath,
        "-out", outputPath,
        "-v2", "aes-256-cbc",
        "-passout", "pass:\(passphrase)",
    ]
    let stderr = Pipe()
    proc.standardError = stderr
    proc.standardOutput = Pipe()
    try proc.run()
    proc.waitUntilExit()
    guard proc.terminationStatus == 0 else {
        let errData = stderr.fileHandleForReading.readDataToEndOfFile()
        let errStr = String(data: errData, encoding: .utf8) ?? "<unreadable stderr>"
        struct OpenSSLError: Error, CustomStringConvertible {
            let status: Int32
            let stderr: String
            var description: String { "openssl exited with status \(status): \(stderr)" }
        }
        throw OpenSSLError(status: proc.terminationStatus, stderr: errStr)
    }
}
