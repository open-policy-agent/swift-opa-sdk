import AsyncHTTPClient
import Config
import Foundation
import Logging
import NIOConcurrencyHelpers  // Needed for type NIOLockedValueBox
import NIOCore  // Needed for type TimeAmount
import NIOSSL
import Rego
import Testing

@testable import Runtime

// MARK: - Closure-based HTTPClientConfigSource Tests

/// Covers the `.tls` / `.configuration` provider cases of
/// ``OPA/HTTPClientConfigSource``: per-load invocation, rotation, failure
/// handling, and precedence over `credentials.client_tls`.
@Suite("RuntimeHTTPClientConfigSourceTests")
struct RuntimeHTTPClientConfigSourceTests {

    /// A `connect` timeout no default ever produces, so seeing it on a loader
    /// can only mean the provider's configuration arrived.
    static let marker: TimeAmount = .seconds(19)

    /// Thrown by the deliberately-failing providers.
    enum ProviderFailure: Error, Equatable {
        case identityUnavailable
    }

    // MARK: - Invocation contract

    @Test("a provider is not invoked while constructing the loader")
    func testProviderNotInvokedAtInit() async throws {
        let calls = NIOLockedValueBox(0)
        _ = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(baseURL: "https://example.com"),
            httpClientConfig: .tls {
                calls.withLockedValue { $0 += 1 }
                return TLSConfiguration.makeClientConfiguration()
            })

        #expect(calls.withLockedValue { $0 } == 0, "construction must not perform I/O")
    }

    @Test("a .tls provider is invoked once per load, with no caching in between")
    func testTLSProviderInvokedOnEveryLoad() async throws {
        let server = try await Self.startPlainBundleServer()
        defer { Task { try? await server.shutdown() } }

        let calls = NIOLockedValueBox(0)
        var loader = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(baseURL: server.baseURL),
            httpClientConfig: .tls {
                calls.withLockedValue { $0 += 1 }
                return TLSConfiguration.makeClientConfiguration()
            })

        for _ in 0..<3 {
            _ = try requireBundleLoadSuccess(await loader.load())
        }
        #expect(calls.withLockedValue { $0 } == 3)
    }

    @Test("a .configuration provider is invoked once per load, with no caching in between")
    func testConfigurationProviderInvokedOnEveryLoad() async throws {
        let server = try await Self.startPlainBundleServer()
        defer { Task { try? await server.shutdown() } }

        let calls = NIOLockedValueBox(0)
        var loader = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(baseURL: server.baseURL),
            httpClientConfig: .configuration {
                calls.withLockedValue { $0 += 1 }
                return Self.shortTimeoutConfiguration()
            })

        for _ in 0..<3 {
            _ = try requireBundleLoadSuccess(await loader.load())
        }
        #expect(calls.withLockedValue { $0 } == 3)
    }

    // MARK: - Rotation

    @Test("rotating the .tls provider's identity changes the loader's active configuration")
    func testTLSProviderRotationReachesActiveConfig() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        let secondCert = env.tmpDir.appendingPathComponent("second-client.crt").path
        let secondKey = env.tmpDir.appendingPathComponent("second-client.key").path
        try generateTestCertificate(certPath: secondCert, keyPath: secondKey, serialNumber: 51)

        let server = try await Self.startPlainBundleServer()
        defer { Task { try? await server.shutdown() } }

        let identities = RotatingIdentities([
            (cert: env.clientCert, key: env.clientKey),
            (cert: secondCert, key: secondKey),
        ])
        var loader = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(baseURL: server.baseURL),
            httpClientConfig: .tls {
                let identity = identities.next()
                return try Self.clientTLSConfiguration(
                    certPath: identity.cert, keyPath: identity.key, trusting: env.serverCert)
            })

        _ = try requireBundleLoadSuccess(await loader.load())
        let first = try #require(loader.httpClientConfig.tlsConfiguration?.certificateChain)
        #expect(!first.isEmpty)

        _ = try requireBundleLoadSuccess(await loader.load())
        let second = try #require(loader.httpClientConfig.tlsConfiguration?.certificateChain)

        #expect(first != second, "the rotated identity must reach the active configuration")
    }

    @Test("a rotated .configuration provider recovers on the load after a rejected identity")
    func testConfigurationProviderRotationRecoversOnNextLoad() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        let rogueCert = env.tmpDir.appendingPathComponent("rogue-client.crt").path
        let rogueKey = env.tmpDir.appendingPathComponent("rogue-client.key").path
        try generateTestCertificate(certPath: rogueCert, keyPath: rogueKey, serialNumber: 52)

        let server = try await Self.startMTLSBundleServer(env: env)
        defer { Task { try? await server.shutdown() } }

        let identities = RotatingIdentities([
            (cert: rogueCert, key: rogueKey),
            (cert: env.clientCert, key: env.clientKey),
        ])
        var loader = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(baseURL: server.baseURL),
            httpClientConfig: .configuration {
                let identity = identities.next()
                var clientConfig = Self.shortTimeoutConfiguration()
                clientConfig.tlsConfiguration = try Self.clientTLSConfiguration(
                    certPath: identity.cert, keyPath: identity.key, trusting: env.serverCert)
                return clientConfig
            })

        _ = try requireBundleLoadFailure(
            await loader.load(), context: "the mTLS server does not trust the rogue identity")
        _ = try requireBundleLoadSuccess(
            await loader.load(), context: "the rotated identity is trusted")
    }

    @Test("provider rotation is picked up by the Runtime's polling loop")
    func testProviderRotationThroughRuntimePolling() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        let rogueCert = env.tmpDir.appendingPathComponent("rogue-client.crt").path
        let rogueKey = env.tmpDir.appendingPathComponent("rogue-client.key").path
        try generateTestCertificate(certPath: rogueCert, keyPath: rogueKey, serialNumber: 53)

        let server = try await Self.startMTLSBundleServer(env: env)
        defer { Task { try? await server.shutdown() } }

        let identities = RotatingIdentities([
            (cert: rogueCert, key: rogueKey),
            (cert: env.clientCert, key: env.clientKey),
        ])
        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfigWithPolling(baseURL: server.baseURL).utf8))
        let rt = try OPA.Runtime(
            config: config,
            httpClientConfig: .configuration {
                let identity = identities.next()
                var clientConfig = Self.shortTimeoutConfiguration()
                clientConfig.tlsConfiguration = try Self.clientTLSConfiguration(
                    certPath: identity.cert, keyPath: identity.key, trusting: env.serverCert)
                return clientConfig
            })

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }

        let result = try #require(
            await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(20)) { result in
                if case .success = result { return true }
                return false
            },
            "the rotated identity never produced a successful poll")
        _ = try requireBundleLoadSuccess(result)
    }

    // MARK: - Provider failure

    @Test("a provider throw surfaces as the load failure verbatim")
    func testProviderThrowSurfacesAsLoadFailure() async throws {
        var loader = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(baseURL: "https://example.com"),
            httpClientConfig: .tls { throw ProviderFailure.identityUnavailable })

        let error = try requireBundleLoadFailure(await loader.load())
        #expect(
            error as? ProviderFailure == .identityUnavailable,
            "the provider's error must be neither swallowed nor rewrapped, got \(error)")
    }

    @Test("a throwing provider is retried on the next load")
    func testProviderThrowIsRetriedOnNextLoad() async throws {
        let server = try await Self.startPlainBundleServer()
        defer { Task { try? await server.shutdown() } }

        let calls = NIOLockedValueBox(0)
        var loader = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(baseURL: server.baseURL),
            httpClientConfig: .tls {
                let call = calls.withLockedValue {
                    $0 += 1
                    return $0
                }
                guard call > 2 else { throw ProviderFailure.identityUnavailable }
                return TLSConfiguration.makeClientConfiguration()
            })

        _ = try requireBundleLoadFailure(await loader.load())
        _ = try requireBundleLoadFailure(await loader.load())
        _ = try requireBundleLoadSuccess(await loader.load())
        #expect(calls.withLockedValue { $0 } == 3)
    }

    @Test("a provider throw short-circuits before any HTTP request is issued")
    func testProviderThrowIssuesNoHTTPRequest() async throws {
        // OAuth2 credentials, so a resolution-after-prepare ordering would leave
        // a token request behind on the wire.
        let servers = try await startOAuth2TestServers()
        defer { servers.shutdown() }

        var loader = try makeRESTClientBundleLoader(
            configJSON: oauth2ConfigJSON(servers: servers, extra: ""),
            httpClientConfig: .configuration { throw ProviderFailure.identityUnavailable })

        _ = try requireBundleLoadFailure(await loader.load())
        #expect(servers.bundle.state.requests.isEmpty, "no bundle request must be issued")
        #expect(
            servers.token.state.requests.isEmpty,
            "configuration resolution must run before the OAuth2 token request")
    }

    // MARK: - What the provider controls

    @Test(".configuration supplies the whole configuration, timeouts included")
    func testConfigurationProviderSuppliesWholeConfiguration() async throws {
        let server = try await Self.startPlainBundleServer()
        defer { Task { try? await server.shutdown() } }

        var loader = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(baseURL: server.baseURL),
            httpClientConfig: .configuration {
                var clientConfig = HTTPClient.Configuration()
                clientConfig.timeout = HTTPClient.Configuration.Timeout(
                    connect: Self.marker, read: .seconds(19))
                return clientConfig
            })

        _ = try requireBundleLoadSuccess(await loader.load())
        #expect(loader.httpClientConfig.timeout.connect == Self.marker)
    }

    @Test(".tls uses the provider's TLSConfiguration verbatim, with no minimum-version floor")
    func testTLSProviderConfigurationUsedVerbatim() async throws {
        let server = try await Self.startPlainBundleServer()
        defer { Task { try? await server.shutdown() } }

        var loader = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(baseURL: server.baseURL),
            httpClientConfig: .tls {
                var tls = TLSConfiguration.makeClientConfiguration()
                tls.minimumTLSVersion = .tlsv1
                tls.certificateVerification = .none
                return tls
            })

        _ = try requireBundleLoadSuccess(await loader.load())
        let active = try #require(loader.httpClientConfig.tlsConfiguration)
        #expect(active.certificateVerification == .none, "this must be the provider's own object")
        #expect(
            active.minimumTLSVersion == .tlsv1,
            "no TLS 1.2 floor is imposed; composing one is the caller's job")
    }

    // MARK: - Precedence over credentials.client_tls

    @Test(".tls beats credentials.client_tls on the wire")
    func testTLSProviderOverridesClientTLSOnTheWire() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        // The server trusts only `env.clientCert`, which the provider presents.
        // `credentials.client_tls` points at an identity it rejects.
        let rogueCert = env.tmpDir.appendingPathComponent("rogue-client.crt").path
        let rogueKey = env.tmpDir.appendingPathComponent("rogue-client.key").path
        try generateTestCertificate(certPath: rogueCert, keyPath: rogueKey, serialNumber: 54)

        let server = try await Self.startMTLSBundleServer(env: env)
        defer { Task { try? await server.shutdown() } }

        var loader = try makeRESTClientBundleLoader(
            configJSON: Self.clientTLSConfigJSON(
                baseURL: server.baseURL, cert: rogueCert, privateKey: rogueKey,
                caCert: env.serverCert),
            httpClientConfig: .tls {
                try Self.clientTLSConfiguration(
                    certPath: env.clientCert, keyPath: env.clientKey, trusting: env.serverCert)
            })

        _ = try requireBundleLoadSuccess(
            await loader.load(),
            context: "the provider's identity, not the config file's, must reach the handshake")
    }

    @Test(".tls with credentials.client_tls never reads the configured cert files")
    func testTLSProviderWithClientTLSNeverReadsCertFiles() async throws {
        let server = try await Self.startPlainBundleServer()
        defer { Task { try? await server.shutdown() } }

        let missing = "/tmp/nonexistent-\(UUID().uuidString)"
        var loader = try makeRESTClientBundleLoader(
            configJSON: Self.clientTLSConfigJSON(
                baseURL: server.baseURL, cert: "\(missing).crt", privateKey: "\(missing).key"),
            httpClientConfig: .tls { TLSConfiguration.makeClientConfiguration() })

        _ = try requireBundleLoadSuccess(
            await loader.load(), context: "the client_tls cert paths must never be opened")
    }

    @Test(".tls with credentials.client_tls warns once, naming the ignored cert path")
    func testTLSProviderWarnsWhenOverridingClientTLS() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        let capture = CapturingLogHandler()
        _ = try makeRESTClientBundleLoader(
            configJSON: Self.clientTLSConfigJSON(
                baseURL: "https://example.com", cert: env.clientCert, privateKey: env.clientKey),
            httpClientConfig: .tls { TLSConfiguration.makeClientConfiguration() },
            logger: Logger(label: "test.http-client-config-source") { _ in capture })

        let warnings = capture.messages(atLeast: .warning)
        #expect(warnings.count == 1, "expected exactly one warning, got \(warnings)")
        let warning = try #require(warnings.first)
        #expect(warning.contains("credentials.client_tls"))
        #expect(warning.contains(env.clientCert))
    }

    @Test("credentials.client_tls with a fixed configuration does not warn")
    func testFixedConfigurationWithClientTLSDoesNotWarn() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        let capture = CapturingLogHandler()
        _ = try makeRESTClientBundleLoader(
            configJSON: Self.clientTLSConfigJSON(
                baseURL: "https://example.com", cert: env.clientCert, privateKey: env.clientKey),
            httpClientConfig: .fixed(HTTPClient.Configuration()),
            logger: Logger(label: "test.http-client-config-source") { _ in capture })

        #expect(
            capture.messages(atLeast: .warning).isEmpty,
            "a fixed configuration still lets client_tls supply the TLS settings")
    }

    // MARK: - Discovery

    @Test("DiscoveryConfigProvider forwards a provider source to the discovery loader")
    func testDiscoveryProviderSourceIsForwarded() async throws {
        let id = RecordingHTTPLoaderRegistry.shared.register()
        defer { RecordingHTTPLoaderRegistry.shared.unregister(id: id) }

        let bootConfig = try JSONDecoder().decode(
            OPA.Config.self, from: Data(Self.recordingDiscoveryConfigJSON(id: id).utf8))

        _ = try OPA.DiscoveryConfigProvider(
            bootConfig: bootConfig,
            bundleLoaders: [OPA.RecordingHTTPBundleLoader.self],
            httpClientConfig: .tls { TLSConfiguration.makeClientConfiguration() })

        let observed = try #require(
            RecordingHTTPLoaderRegistry.shared.observation(id: id),
            "recording loader was never constructed")
        guard case .tls = observed.httpClientConfig else {
            Issue.record("expected a .tls source, got \(String(describing: observed.httpClientConfig))")
            return
        }
    }

    @Test("Runtime forwards a provider source to the auto-built DiscoveryConfigProvider")
    func testRuntimeForwardsProviderToAutoBuiltDiscoveryProvider() async throws {
        let id = RecordingHTTPLoaderRegistry.shared.register()
        defer { RecordingHTTPLoaderRegistry.shared.unregister(id: id) }

        let bootConfig = try JSONDecoder().decode(
            OPA.Config.self, from: Data(Self.recordingDiscoveryConfigJSON(id: id).utf8))

        _ = try OPA.Runtime(
            config: bootConfig,
            httpClientConfig: .configuration { Self.shortTimeoutConfiguration() },
            bundleLoaders: [OPA.RecordingHTTPBundleLoader.self])

        let observed = try #require(
            RecordingHTTPLoaderRegistry.shared.observation(id: id),
            "recording loader was never constructed")
        guard case .configuration = observed.httpClientConfig else {
            Issue.record("expected a .configuration source, got \(String(describing: observed.httpClientConfig))")
            return
        }
    }

    // MARK: - Test-Local Helpers

    /// Timeouts short enough that a rejected handshake or an unreachable host
    /// surfaces inside a test's wait periods. The global default uses 90s.
    private static func shortTimeoutConfiguration() -> HTTPClient.Configuration {
        var clientConfig = HTTPClient.Configuration()
        clientConfig.timeout = HTTPClient.Configuration.Timeout(connect: .seconds(5), read: .seconds(5))
        return clientConfig
    }

    private static func clientTLSConfiguration(
        certPath: String,
        keyPath: String,
        trusting caCertPath: String
    ) throws -> TLSConfiguration {
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.minimumTLSVersion = .tlsv12
        tls.certificateChain = try NIOSSLCertificate.fromPEMFile(certPath).map { .certificate($0) }
        tls.privateKey = .privateKey(try NIOSSLPrivateKey(file: keyPath, format: .pem))
        tls.trustRoots = .certificates(try NIOSSLCertificate.fromPEMFile(caCertPath))
        return tls
    }

    private static func startPlainBundleServer() async throws -> TestBundleServer {
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        return try await TestBundleServer.start(files: ["/bundles/test.tar.gz": bundleData])
    }

    private static func startMTLSBundleServer(env: ClientTLSEnv) async throws -> TestBundleServer {
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        return try await TestBundleServer.start(
            files: ["/bundles/test.tar.gz": bundleData],
            tls: TestBundleServerTLSOptions(
                serverCertPath: env.serverCert,
                serverKeyPath: env.serverKey,
                clientCACertPath: env.clientCert))
    }

    private static func clientTLSConfigJSON(
        baseURL: String,
        cert: String,
        privateKey: String,
        caCert: String? = nil
    ) -> String {
        let tlsBlock = caCert.map { "\"tls\": {\"ca_cert\": \"\($0)\"}," } ?? ""
        return """
            {
              "services": {
                "test-svc": {
                  "url": "\(baseURL)",
                  \(tlsBlock)
                  "credentials": {
                    "client_tls": {
                      "cert": "\(cert)",
                      "private_key": "\(privateKey)"
                    }
                  }
                }
              },
              "bundles": {
                "test": {"service": "test-svc", "resource": "/bundles/test.tar.gz"}
              }
            }
            """
    }

    /// Boot config whose `discovery` section selects
    /// ``OPA/RecordingHTTPBundleLoader`` via `plugins.recording_loader.id`.
    private static func recordingDiscoveryConfigJSON(id: String) -> String {
        """
        {
            "services": {"svc": {"url": "https://example.com"}},
            "discovery": {
                "service": "svc",
                "resource": "/discovery",
                "decision": "discovery/config"
            },
            "plugins": {"recording_loader": {"id": "\(id)"}}
        }
        """
    }
}

// MARK: - Rotating Identities

/// Hands out cert/key path pairs by call index, repeating the last pair once
/// the list is exhausted.
final class RotatingIdentities: @unchecked Sendable {
    private let lock = NSLock()
    private let pairs: [(cert: String, key: String)]
    private var index = 0

    init(_ pairs: [(cert: String, key: String)]) {
        precondition(!pairs.isEmpty)
        self.pairs = pairs
    }

    func next() -> (cert: String, key: String) {
        lock.withLock {
            let pair = pairs[min(index, pairs.count - 1)]
            index += 1
            return pair
        }
    }
}

// MARK: - Capturing Log Handler

/// A `LogHandler` that records everything logged through it, so tests can
/// assert on warnings.
///
/// `LoggingSystem.bootstrap` can only be called once per process (see
/// ``TestLogging``), so this is installed per-`Logger` via
/// `Logger(label:factory:)` rather than registered globally.
final class CapturingLogHandler: LogHandler, @unchecked Sendable {
    struct Entry: Sendable {
        let level: Logger.Level
        let message: String
    }

    private let lock = NSLock()
    private var entries: [Entry] = []

    var metadata: Logger.Metadata = [:]
    var logLevel: Logger.Level = .trace

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    func log(event: LogEvent) {
        lock.withLock { entries.append(Entry(level: event.level, message: event.message.description)) }
    }

    /// Messages logged at or above `level`.
    func messages(atLeast level: Logger.Level) -> [String] {
        lock.withLock { entries.filter { $0.level >= level }.map(\.message) }
    }
}
