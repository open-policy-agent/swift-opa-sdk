import AsyncHTTPClient
import NIOSSL
import Rego

extension OPA {
    /// Supplies a `TLSConfiguration` on demand.
    public typealias TLSConfigurationProvider = @Sendable () async throws -> TLSConfiguration

    /// Supplies a complete `HTTPClient.Configuration` on demand.
    public typealias HTTPClientConfigurationProvider = @Sendable () async throws -> HTTPClient.Configuration

    /// Where an HTTP bundle loader gets its `HTTPClient.Configuration`.
    ///
    /// The closure cases are invoked on every `load()` and make the caller the
    /// sole owner of TLS: nothing from the OPA config contributes to
    /// `tlsConfiguration`.
    public enum HTTPClientConfigSource: Sendable {
        /// A configuration fixed at construction time.
        case fixed(HTTPClient.Configuration)

        /// TLS from the provider; every other field from `HTTPClient.Configuration.singletonConfiguration`.
        case tls(TLSConfigurationProvider)

        /// The whole configuration from the provider, timeouts included.
        case configuration(HTTPClientConfigurationProvider)
    }
}
