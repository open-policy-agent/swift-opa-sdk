import AsyncHTTPClient
import Config
import Crypto
import Foundation
import NIOConcurrencyHelpers
import NIOCore  // Needed for type TimeAmount
import NIOHTTP1  // Needed for type HTTPHeaders
import NIOSSL
import Rego

extension OPA {
    /// Emulates the same functionality as the `rest.clientTLSAuthPlugin` type from OPA.
    public struct ClientTLSAuthPluginLoader: Sendable {
        public let config: ClientTLSAuthPlugin

        /// Reference-typed cache so this struct stays `Sendable` (and cheap to
        /// copy) while still mirroring the Go plugin's cached-cert behavior.
        private let certCache: CertCache

        public init(config: ClientTLSAuthPlugin) {
            self.config = config
            self.certCache = CertCache()
        }

        /// ``prepare`` does not change any request headers for this credential type.
        public func prepare(req: inout HTTPClientRequest) throws {
            return
        }

        /// Builds an `HTTPClient.Configuration` configured for mutual TLS,
        /// layered on top of an optional base configuration. Mirrors
        /// `clientTLSAuthPlugin.NewClient` from the Go OPA codebase.
        ///
        /// - Parameters:
        ///   - service: The owning service's config (provides URL + server TLS settings).
        ///   - base: A base configuration to override; defaults to `.singletonConfiguration`.
        public func newHTTPClientConfig(
            service: ServiceConfig,
            base: HTTPClient.Configuration = .singletonConfiguration
        ) throws -> HTTPClient.Configuration {
            // `ClientTLSAuthPlugin.validate()` already enforces non-empty
            // `cert` and `privateKey`, but we stay defensive here.
            guard !config.cert.isEmpty else {
                throw RuntimeError(
                    code: .internalError,
                    message: "client certificate is needed when client TLS is enabled"
                )
            }
            guard !config.privateKey.isEmpty else {
                throw RuntimeError(
                    code: .internalError,
                    message: "private key is needed when client TLS is enabled"
                )
            }

            var tlsConfig = try buildBaseTLSConfig(service: service)

            // Attach client cert/key (mTLS). In Go this is wired via
            // `GetClientCertificate` for per-handshake reload; NIOSSL has no
            // direct equivalent, so we load at config-build time. The outer
            // `RESTClientBundleLoader` is responsible for rebuilding the
            // HTTPClient when config/cert changes happen on disk.
            let (chain, key) = try loadCertificate()
            tlsConfig.certificateChain = chain.map { .certificate($0) }
            tlsConfig.privateKey = .privateKey(key)

            // Deprecated plugin-level `ca_cert` is applied only when the
            // service config did not provide one. (Matches the Go plugin's
            // fallback order in `clientTLSAuthPlugin.NewClient`.)
            let serviceHasCA = !(service.tls?.caCert?.isEmpty ?? true)
            if !serviceHasCA, let caCertPath = config.caCert, !caCertPath.isEmpty {
                // TODO: Emit deprecation warning once a logger is wired in:
                //   "Deprecated 'services[_].credentials.client_tls.ca_cert' configuration specified.
                //    Use 'services[_].tls.ca_cert' instead."
                try Self.applyTrustRoots(
                    to: &tlsConfig,
                    userCACertPath: caCertPath,
                    systemCARequired: config.systemCARequired ?? false
                )
            }

            var clientConfig = base
            clientConfig.tlsConfiguration = tlsConfig
            if let secs = service.responseHeaderTimeoutSeconds {
                clientConfig.timeout = HTTPClient.Configuration.Timeout(
                    connect: clientConfig.timeout.connect,
                    read: .seconds(secs)
                )
            }
            return clientConfig
        }

        // MARK: - TLS config building

        /// The minimum TLS version used by OPA REST clients by default.
        /// Mirrors Go's `config.DefaultMinTLSVersion = tls.VersionTLS12`.
        private static let defaultMinTLSVersion: TLSVersion = .tlsv12

        /// Equivalent of DefaultTLSConfig in Go OPA.
        private func buildBaseTLSConfig(service: ServiceConfig) throws -> TLSConfiguration {
            var t = TLSConfiguration.makeClientConfiguration()

            // Future: If/when minTLSVersion is exposed on the service
            // config, allow overriding this setting.
            t.minimumTLSVersion = Self.defaultMinTLSVersion

            if service.url.scheme == "https", service.allowInsecureTLS == true {
                t.certificateVerification = .none
            }

            if let tlsCfg = service.tls,
                let caCertPath = tlsCfg.caCert,
                !caCertPath.isEmpty
            {
                try Self.applyTrustRoots(
                    to: &t,
                    userCACertPath: caCertPath,
                    systemCARequired: tlsCfg.systemCARequired ?? false
                )
            }
            return t
        }

        /// Applies the "always append user CA; optionally include system roots too"
        /// semantics from Go's `DefaultTLSConfig` onto a `TLSConfiguration`.
        ///
        /// This relies on NIOSSL's `additionalTrustRoots`, which layers extra
        /// roots on top of `trustRoots`.
        fileprivate static func applyTrustRoots(
            to tls: inout TLSConfiguration,
            userCACertPath: String?,
            systemCARequired: Bool
        ) throws {
            guard let path = userCACertPath, !path.isEmpty else {
                // No user CA. Leave `trustRoots` at its default (`.default`),
                // which is the system trust store.
                return
            }

            let caBytes = try Data(contentsOf: URL(fileURLWithPath: path))
            let caCerts = try NIOSSLCertificate.fromPEMBytes(Array(caBytes))

            if systemCARequired {
                // System roots + user CA.
                tls.trustRoots = .default
                tls.additionalTrustRoots = [.certificates(caCerts)]
            } else {
                // Only the user CA.
                tls.trustRoots = .certificates(caCerts)
                tls.additionalTrustRoots = []
            }
        }

        // MARK: - loadCertificate

        /// Ported from the Go plugin's cached-cert logic.
        private func loadCertificate() throws -> ([NIOSSLCertificate], NIOSSLPrivateKey) {
            let rereadInterval = config.certRereadIntervalSeconds ?? 0

            // Fast path: within the re-read window, return the cached value.
            if let cached = certCache.snapshot(),
                rereadInterval > 0,
                Date().timeIntervalSince(cached.lastLoadTime) < Double(rereadInterval)
            {
                return (cached.chain, cached.key)
            }

            let certPEM = try Data(contentsOf: URL(fileURLWithPath: config.cert))
            let keyData = try Data(contentsOf: URL(fileURLWithPath: config.privateKey))

            let certHash = SHA256.hash(data: certPEM)
            let keyHash = SHA256.hash(data: keyData)

            // Same bytes on disk: reuse the cached/parsed cert.
            if let cached = certCache.snapshot(),
                cached.certHash == certHash,
                cached.keyHash == keyHash
            {
                return (cached.chain, cached.key)
            }

            let chain = try NIOSSLCertificate.fromPEMBytes(Array(certPEM))

            // NIOSSL understands PKCS#1, PKCS#8, and encrypted PEM natively.
            // This replaces the Go code's manual re-encoding flow.
            let passphrase = config.privateKeyPassphrase ?? ""
            let key = try NIOSSLPrivateKey(
                bytes: Array(keyData),
                format: .pem
            ) { setter in
                setter(Array(passphrase.utf8))
            }

            certCache.store(
                CertCache.Entry(
                    chain: chain,
                    key: key,
                    certHash: certHash,
                    keyHash: keyHash,
                    lastLoadTime: Date()
                )
            )
            return (chain, key)
        }
    }
}

// MARK: - Internal cert cache

/// Reference-typed cache for the parsed client cert chain and private key.
/// Used by `ClientTLSAuthPluginLoader` so the outer struct remains a `Sendable`
/// value type while still supporting mutation of cached state across calls.
private final class CertCache: @unchecked Sendable {
    struct Entry {
        let chain: [NIOSSLCertificate]
        let key: NIOSSLPrivateKey
        let certHash: SHA256Digest
        let keyHash: SHA256Digest
        let lastLoadTime: Date
    }

    private let lock = NIOLock()
    private var entry: Entry?

    func snapshot() -> Entry? {
        lock.withLock { entry }
    }

    func store(_ e: Entry) {
        lock.withLock { entry = e }
    }
}
