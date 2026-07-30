import AsyncHTTPClient
import Config
import Foundation
import Logging
import NIOCore  // Needed for type TimeAmount
import NIOSSL
import Rego
import Testing

@testable import Runtime

// MARK: - Programmatically-Injected HTTPClient.Configuration Tests

extension OPA.HTTPClientConfigSource {
    var fixedConfigurationForTesting: HTTPClient.Configuration? {
        guard case .fixed(let cfg) = self else { return nil }
        return cfg
    }
}

/// These tests exercise the Runtime's ability to pass down an ``HTTPClient\Configuration``
/// instance to the bundle loaders.
@Suite("RuntimeInjectedHTTPClientConfigTests")
struct RuntimeInjectedHTTPClientConfigTests {

    /// A non-default `connect` timeout. If we see this value on a loader,
    /// it means the injected configuration populated correctly.
    static let marker: TimeAmount = .seconds(17)

    private static func markerConfig() -> HTTPClient.Configuration {
        var cfg = HTTPClient.Configuration()
        cfg.timeout = HTTPClient.Configuration.Timeout(connect: Self.marker, read: .seconds(23))
        return cfg
    }

    // MARK: - Regular bundle loaders

    @Test("injected httpClientConfig reaches the loader built by getBundleLoader")
    func testInjectedConfigReachesBundleLoader() async throws {
        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfig(baseURL: "https://example.com").utf8))
        let rt = try OPA.Runtime(config: config, httpClientConfig: .fixed(Self.markerConfig()))

        // The Runtime keeps the injected value verbatim.
        #expect(rt.httpClientConfig?.fixedConfigurationForTesting?.timeout.connect == Self.marker)

        // The Runtime hands the same config to the loader it constructs.
        let loader = try rt.getBundleLoader(name: "test", config: config, logger: rt.logger)
        let restLoader = try #require(
            loader as? OPA.RESTClientBundleLoader,
            "expected RESTClientBundleLoader, got \(type(of: loader))")
        #expect(
            restLoader.httpClientConfig.timeout.connect == Self.marker,
            "injected httpClientConfig must reach the bundle loader")
        #expect(restLoader.httpClientConfig.timeout.read == .seconds(23))
    }

    @Test("injected httpClientConfig and injected headers both reach the loader")
    func testInjectedConfigAndHeadersCoexist() async throws {
        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfig(baseURL: "https://example.com").utf8))
        let rt = try OPA.Runtime(
            config: config,
            headers: ["x-injected": "hello"],
            httpClientConfig: .fixed(Self.markerConfig()))

        let loader = try rt.getBundleLoader(name: "test", config: config, logger: rt.logger)
        let restLoader = try #require(loader as? OPA.RESTClientBundleLoader)
        #expect(restLoader.customHeaders == ["x-injected": "hello"])
        #expect(restLoader.httpClientConfig.timeout.connect == Self.marker)
    }

    // MARK: - Default (no injection) case

    @Test("no injection: loader receives the default http client config")
    func testDefaultCaseMatchesSingletonConfiguration() async throws {
        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfig(baseURL: "https://example.com").utf8))
        let rt = try OPA.Runtime(config: config)

        let loader = try rt.getBundleLoader(name: "test", config: config, logger: rt.logger)
        let restLoader = try #require(loader as? OPA.RESTClientBundleLoader)

        let singleton = HTTPClient.Configuration.singletonConfiguration
        #expect(restLoader.httpClientConfig.timeout.connect == singleton.timeout.connect)
        #expect(restLoader.httpClientConfig.timeout.read == singleton.timeout.read)

        // Check against a loader that used its own default from `nil`.
        let derived = try OPA.RESTClientBundleLoader(
            config: config,
            bundleResourceName: "test",
            etag: nil,
            headers: nil,
            httpClientConfig: nil)
        #expect(restLoader.httpClientConfig.timeout.connect == derived.httpClientConfig.timeout.connect)
        #expect(restLoader.httpClientConfig.timeout.read == derived.httpClientConfig.timeout.read)
    }

    @Test("no injection: bundle still fetches end-to-end from the test bundle server")
    func testDefaultCaseStillFetchesEndToEnd() async throws {
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        let server = try await TestBundleServer.start(files: [
            "/bundles/test.tar.gz": bundleData
        ])
        defer { Task { try? await server.shutdown() } }

        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfig(baseURL: server.baseURL).utf8))
        let rt = try OPA.Runtime(config: config)

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }

        let result = try #require(
            await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(10)),
            "bundle never loaded")
        _ = try requireBundleLoadSuccess(result)

        let dr = try await rt.decision("data/foo/hello", input: nil)
        #expect(dr.result.first == ["result": 1])
    }

    @Test("explicitly injected default http client config also fetches end-to-end")
    func testInjectedSingletonFetchesEndToEnd() async throws {
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        let server = try await TestBundleServer.start(files: [
            "/bundles/test.tar.gz": bundleData
        ])
        defer { Task { try? await server.shutdown() } }

        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfig(baseURL: server.baseURL).utf8))
        let rt = try OPA.Runtime(
            config: config,
            httpClientConfig: .fixed(HTTPClient.Configuration.singletonConfiguration))

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }

        let result = try #require(
            await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(10)),
            "bundle never loaded")
        _ = try requireBundleLoadSuccess(result)
    }

    // MARK: - Discovery

    /// `DiscoveryConfigProvider.loader` is `private`, so rather than weaken
    /// access control we register a recording loader type through
    /// `bundleLoaders:` (the pattern established by
    /// `Utils+MockBundleLoader.swift`) and read what it was handed.
    @Test("DiscoveryConfigProvider httpClientConfig param reaches the loader it constructs")
    func testDiscoveryConfigProviderConfigParam() async throws {
        let id = RecordingHTTPLoaderRegistry.shared.register()
        defer { RecordingHTTPLoaderRegistry.shared.unregister(id: id) }

        let bootConfig = try JSONDecoder().decode(
            OPA.Config.self, from: Data(Self.recordingDiscoveryConfigJSON(id: id).utf8))

        _ = try OPA.DiscoveryConfigProvider(
            bootConfig: bootConfig,
            bundleLoaders: [OPA.RecordingHTTPBundleLoader.self],
            headers: ["x-provider-injected": "yes"],
            httpClientConfig: .fixed(Self.markerConfig()))

        let observed = try #require(
            RecordingHTTPLoaderRegistry.shared.observation(id: id),
            "recording loader was never constructed")
        #expect(observed.builtViaHTTPInit, "loader must be built through the HTTP discovery init")
        #expect(
            observed.httpClientConfig?.fixedConfigurationForTesting?.timeout.connect == Self.marker,
            "DiscoveryConfigProvider must forward httpClientConfig to the discovery loader")
        #expect(observed.headers == ["x-provider-injected": "yes"])
    }

    @Test("Runtime forwards its httpClientConfig to the auto-built DiscoveryConfigProvider")
    func testRuntimeForwardsConfigToDiscoveryProvider() async throws {
        let id = RecordingHTTPLoaderRegistry.shared.register()
        defer { RecordingHTTPLoaderRegistry.shared.unregister(id: id) }

        let bootConfig = try JSONDecoder().decode(
            OPA.Config.self, from: Data(Self.recordingDiscoveryConfigJSON(id: id).utf8))

        _ = try OPA.Runtime(
            config: bootConfig,
            httpClientConfig: .fixed(Self.markerConfig()),
            bundleLoaders: [OPA.RecordingHTTPBundleLoader.self])

        let observed = try #require(
            RecordingHTTPLoaderRegistry.shared.observation(id: id),
            "recording loader was never constructed")
        #expect(
            observed.httpClientConfig?.fixedConfigurationForTesting?.timeout.connect == Self.marker,
            "Runtime must forward httpClientConfig into DiscoveryConfigProvider")
    }

    @Test("Runtime with no injection forwards nil rather than coalescing to a default")
    func testRuntimeDoesNotCoalesceNilHTTPClientConfig() async throws {
        let id = RecordingHTTPLoaderRegistry.shared.register()
        defer { RecordingHTTPLoaderRegistry.shared.unregister(id: id) }

        let bootConfig = try JSONDecoder().decode(
            OPA.Config.self, from: Data(Self.recordingDiscoveryConfigJSON(id: id).utf8))

        let rt = try OPA.Runtime(
            config: bootConfig,
            bundleLoaders: [OPA.RecordingHTTPBundleLoader.self])

        // nil coalescing here would erase "the caller injected nothing", which is
        // what lets a loader decide whether `services[_].tls` applies.
        #expect(rt.httpClientConfig == nil)

        let observed = try #require(
            RecordingHTTPLoaderRegistry.shared.observation(id: id),
            "recording loader was never constructed")
        #expect(observed.httpClientConfig == nil)
    }

    @Test("DiscoveryConfigProvider with no httpClientConfig forwards nil, and the loader defaults")
    func testDiscoveryConfigProviderDefaultCase() async throws {
        let id = RecordingHTTPLoaderRegistry.shared.register()
        defer { RecordingHTTPLoaderRegistry.shared.unregister(id: id) }

        let bootConfig = try JSONDecoder().decode(
            OPA.Config.self, from: Data(Self.recordingDiscoveryConfigJSON(id: id).utf8))

        _ = try OPA.DiscoveryConfigProvider(
            bootConfig: bootConfig,
            bundleLoaders: [OPA.RecordingHTTPBundleLoader.self])

        let observed = try #require(RecordingHTTPLoaderRegistry.shared.observation(id: id))
        #expect(
            observed.httpClientConfig == nil,
            "a nil httpClientConfig must be forwarded as nil so the loader applies its own default")
    }

    // MARK: - mTLS

    /// Test pulling mTLS configuration from the ``HTTPClient/Configuration``
    @Test("injected client-certificate configuration completes a real mTLS bundle fetch")
    func testInjectedMTLSEndToEnd() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        let server = try await TestBundleServer.start(
            files: ["/bundles/test.tar.gz": bundleData],
            tls: TestBundleServerTLSOptions(
                serverCertPath: env.serverCert,
                serverKeyPath: env.serverKey,
                clientCACertPath: env.clientCert))
        defer { Task { try? await server.shutdown() } }

        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfig(baseURL: server.baseURL).utf8))

        var injected = HTTPClient.Configuration()
        injected.tlsConfiguration = try Self.clientTLSConfiguration(env: env)
        let rt = try OPA.Runtime(config: config, httpClientConfig: .fixed(injected))

        // The configuration must make it to the loader.
        let loader = try rt.getBundleLoader(name: "test", config: config, logger: rt.logger)
        let restLoader = try #require(loader as? OPA.RESTClientBundleLoader)
        #expect(
            restLoader.httpClientConfig.tlsConfiguration?.certificateChain.isEmpty == false,
            "injected client certificate chain must reach the loader")
        #expect(restLoader.httpClientConfig.tlsConfiguration?.privateKey != nil)

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }

        let result = try #require(
            await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(15)),
            "bundle never loaded")
        _ = try requireBundleLoadSuccess(
            result, context: "injected client certificate should satisfy the mTLS server")

        let dr = try await rt.decision("data/foo/hello", input: nil)
        #expect(dr.result.first == ["result": 1])
    }

    /// Negative control for the test above, and a second angle on the same
    /// wiring: the injected configuration trusts the server's CA (so we get
    /// far enough for the server to ask for a client certificate) but carries
    /// no client identity, and the mTLS server rejects the handshake. Both
    /// halves depend on the injected configuration actually reaching the
    /// loader — the trust roots to get past server-cert validation, and the
    /// short timeouts to fail fast.
    ///
    /// Note we cannot express this as "inject nothing": for a service with
    /// `default` (no-auth) credentials, `RESTClientBundleLoader.load()` never
    /// calls `newHTTPClientConfig`, so `services[_].tls.ca_cert` and
    /// `allow_insecure_tls` are not consulted at all and the injected
    /// `HTTPClient.Configuration` is the *only* way to configure TLS. With no
    /// injection the fetch does still fail (BoringSSL
    /// `CERTIFICATE_VERIFY_FAILED` on the self-signed server cert) but only
    /// after `singletonConfiguration`'s 90-second timeout, which is too slow
    /// for a test.
    @Test("injected configuration with no client certificate is rejected by the mTLS server")
    func testMTLSFailsWithoutClientCertificate() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        let server = try await TestBundleServer.start(
            files: ["/bundles/test.tar.gz": bundleData],
            tls: TestBundleServerTLSOptions(
                serverCertPath: env.serverCert,
                serverKeyPath: env.serverKey,
                clientCACertPath: env.clientCert))
        defer { Task { try? await server.shutdown() } }

        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfig(baseURL: server.baseURL).utf8))

        // Trust roots only — no `certificateChain` / `privateKey`.
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.minimumTLSVersion = .tlsv12
        tls.trustRoots = .certificates(try NIOSSLCertificate.fromPEMFile(env.serverCert))
        var injected = HTTPClient.Configuration()
        injected.tlsConfiguration = tls
        injected.timeout = HTTPClient.Configuration.Timeout(connect: .seconds(5), read: .seconds(5))

        let rt = try OPA.Runtime(config: config, httpClientConfig: .fixed(injected))
        var restLoader = try #require(
            try rt.getBundleLoader(name: "test", config: config, logger: rt.logger)
                as? OPA.RESTClientBundleLoader)
        #expect(
            restLoader.httpClientConfig.tlsConfiguration?.certificateChain.isEmpty == true,
            "this configuration deliberately carries no client certificate")

        let result = await restLoader.load()
        _ = try requireBundleLoadFailure(
            result, context: "no client certificate was presented to the mTLS server")
    }

    /// `credentials.client_tls` re-reads its cert on every `load()`, so it beats
    /// a fixed injected configuration for `tlsConfiguration` — while the
    /// injected configuration still supplies every non-TLS field.
    @Test("config-file client TLS wins for tlsConfiguration; injected baseline survives elsewhere")
    func testConfigFileClientTLSWinsOverInjectedTLSConfiguration() async throws {
        let env = try makeClientTLSEnv()
        defer { env.cleanup() }

        // A second, independent client identity that the server does NOT
        // trust. Injecting it proves the config-file cert is the one used:
        // if the injected `tlsConfiguration` survived, the handshake would
        // fail.
        let rogueCert = env.tmpDir.appendingPathComponent("rogue-client.crt").path
        let rogueKey = env.tmpDir.appendingPathComponent("rogue-client.key").path
        try generateTestCertificate(certPath: rogueCert, keyPath: rogueKey, serialNumber: 42)

        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        let server = try await TestBundleServer.start(
            files: ["/bundles/test.tar.gz": bundleData],
            tls: TestBundleServerTLSOptions(
                serverCertPath: env.serverCert,
                serverKeyPath: env.serverKey,
                clientCACertPath: env.clientCert))
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
                "test": {"service": "test-svc", "resource": "/bundles/test.tar.gz"}
              }
            }
            """
        let config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))

        var injected = HTTPClient.Configuration()
        injected.timeout = HTTPClient.Configuration.Timeout(connect: Self.marker, read: .seconds(23))
        injected.tlsConfiguration = try Self.clientTLSConfiguration(
            env: env, clientCertPath: rogueCert, clientKeyPath: rogueKey)

        let rt = try OPA.Runtime(config: config, httpClientConfig: .fixed(injected))
        var restLoader = try #require(
            try rt.getBundleLoader(name: "test", config: config, logger: rt.logger)
                as? OPA.RESTClientBundleLoader)

        // At construction the loader holds the injected configuration verbatim.
        #expect(restLoader.httpClientConfig.timeout.connect == Self.marker)

        // `load()` rebuilds from the injected baseline: the config-file cert
        // replaces the injected `tlsConfiguration`, so the handshake succeeds
        // against a server that only trusts `env.clientCert`.
        let result = await restLoader.load()
        _ = try requireBundleLoadSuccess(
            result, context: "config-file client_tls cert should win over the injected rogue cert")

        // ...and the non-TLS fields of the injected baseline are preserved.
        #expect(
            restLoader.httpClientConfig.timeout.connect == Self.marker,
            "injected configuration must be honored as the client-TLS rebuild baseline")
    }

    // MARK: - Test-Local Helpers

    /// Builds a client-side `TLSConfiguration` presenting `clientCertPath` /
    /// `clientKeyPath` and trusting only the test server's self-signed cert.
    private static func clientTLSConfiguration(
        env: ClientTLSEnv,
        clientCertPath: String? = nil,
        clientKeyPath: String? = nil
    ) throws -> TLSConfiguration {
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.minimumTLSVersion = .tlsv12
        let chain = try NIOSSLCertificate.fromPEMFile(clientCertPath ?? env.clientCert)
        tls.certificateChain = chain.map { .certificate($0) }
        tls.privateKey = .privateKey(
            try NIOSSLPrivateKey(file: clientKeyPath ?? env.clientKey, format: .pem))
        tls.trustRoots = .certificates(try NIOSSLCertificate.fromPEMFile(env.serverCert))
        return tls
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

// MARK: - Recording HTTP Bundle Loader

/// Process-wide registry recording what ``OPA/RecordingHTTPBundleLoader`` was
/// handed at construction time.
///
/// Mirrors ``MockBundleLoaderRegistry``: each test registers a slot under a
/// unique ID and embeds that ID in the OPA config under
/// `plugins.recording_loader.id`, so the loader can bind itself to the right
/// slot while still going through the standard loader-discovery flow.
final class RecordingHTTPLoaderRegistry: @unchecked Sendable {
    static let shared = RecordingHTTPLoaderRegistry()

    struct Observation: Sendable {
        var httpClientConfig: OPA.HTTPClientConfigSource?
        var headers: [String: String]?
        var etag: String?
        /// True when the loader was built through an ``OPA/HTTPBundleLoader``
        /// initializer rather than the plain ``OPA/BundleLoader`` one.
        var builtViaHTTPInit: Bool
    }

    private let lock = NSLock()
    private var slots: [String: Observation?] = [:]

    private init() {}

    /// Register a fresh (empty) slot and return its ID.
    func register() -> String {
        let id = UUID().uuidString
        lock.withLock { slots[id] = Observation?.none }
        return id
    }

    func unregister(id: String) {
        lock.withLock { _ = slots.removeValue(forKey: id) }
    }

    func record(id: String, _ observation: Observation) {
        lock.withLock { slots[id] = observation }
    }

    /// The observation recorded for `id`, or nil if the loader was never built.
    func observation(id: String) -> Observation? {
        lock.withLock { slots[id] ?? nil }
    }
}

extension OPA {
    /// An ``OPA/HTTPBundleLoader`` that records the values it is constructed
    /// with instead of performing any I/O.
    ///
    /// Exists so tests can observe what reaches a discovery loader without
    /// weakening ``OPA/DiscoveryConfigProvider``'s `private var loader`.
    struct RecordingHTTPBundleLoader: OPA.HTTPBundleLoader {
        let id: String

        // MARK: Plain BundleLoader inits

        init(config: OPA.Config, bundleResourceName: String, logger: Logger? = nil) throws {
            self.id = try Self.extractID(from: config)
            Self.record(id: id, httpClientConfig: nil, headers: nil, etag: nil, viaHTTPInit: false)
        }

        init(discoveryConfig config: OPA.Config, logger: Logger? = nil) throws {
            self.id = try Self.extractID(from: config)
            Self.record(id: id, httpClientConfig: nil, headers: nil, etag: nil, viaHTTPInit: false)
        }

        // MARK: HTTPBundleLoader inits

        init(
            config: OPA.Config,
            bundleResourceName: String,
            etag: String?,
            headers: [String: String]?,
            httpClientConfig: OPA.HTTPClientConfigSource?,
            logger: Logger?
        ) throws {
            self.id = try Self.extractID(from: config)
            Self.record(
                id: id, httpClientConfig: httpClientConfig, headers: headers, etag: etag,
                viaHTTPInit: true)
        }

        init(
            discoveryConfig config: OPA.Config,
            etag: String?,
            headers: [String: String]?,
            httpClientConfig: OPA.HTTPClientConfigSource?,
            logger: Logger?
        ) throws {
            self.id = try Self.extractID(from: config)
            Self.record(
                id: id, httpClientConfig: httpClientConfig, headers: headers, etag: etag,
                viaHTTPInit: true)
        }

        // MARK: BundleLoader conformance

        func load() async -> Result<OPA.Bundle, any Error> {
            .failure(
                RuntimeError(
                    code: .internalError,
                    message: "RecordingHTTPBundleLoader does not fetch bundles"))
        }

        func isLongPollingEnabled() -> Bool { false }

        static func compatibleWithConfig(config: OPA.Config, bundleResourceName: String) -> Bool {
            (try? extractID(from: config)) != nil
        }

        static func compatibleWithDiscoveryConfig(config: OPA.Config) -> Bool {
            (try? extractID(from: config)) != nil
        }

        // MARK: Helpers

        private static func record(
            id: String,
            httpClientConfig: OPA.HTTPClientConfigSource?,
            headers: [String: String]?,
            etag: String?,
            viaHTTPInit: Bool
        ) {
            RecordingHTTPLoaderRegistry.shared.record(
                id: id,
                RecordingHTTPLoaderRegistry.Observation(
                    httpClientConfig: httpClientConfig,
                    headers: headers,
                    etag: etag,
                    builtViaHTTPInit: viaHTTPInit))
        }

        /// Pulls `plugins.recording_loader.id` out of the config.
        private static func extractID(from config: OPA.Config) throws -> String {
            guard
                let plugins = config.plugins,
                let entry = plugins["recording_loader"],
                let dict = entry.value as? [String: Any],
                let id = dict["id"] as? String
            else {
                throw RuntimeError(
                    code: .internalError,
                    message: "RecordingHTTPBundleLoader: plugins.recording_loader.id missing"
                )
            }
            return id
        }
    }
}
