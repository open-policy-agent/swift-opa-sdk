import AST
import AsyncHTTPClient
import Config
import Foundation
import Rego

extension OPA {

    /// BundleLoader abstracts over the details of retrieving a bundle.
    public protocol BundleLoader: Sendable {
        /// Needs a public constructor that can build from the config directly.
        init(config: OPA.Config, bundleResourceName: String) throws

        /// Constructor for loading a discovery bundle.
        ///
        /// The loader should read the bundle location from `config.discovery`
        /// rather than `config.bundles`. Loaders that don't support discovery
        /// inherit a default implementation that throws.
        init(discoveryConfig: OPA.Config) throws

        /// Load the bundle, based on the config and any existing state.
        mutating func load() async -> Result<OPA.Bundle, any Swift.Error>

        /// Compatibility check, based on what's in the OPA config.
        static func compatibleWithConfig(config: OPA.Config, bundleResourceName: String) -> Bool

        /// Compatibility check for discovery bundle loading.
        ///
        /// Returns `true` if this loader type can handle fetching the
        /// discovery bundle described by `config.discovery`. The default
        /// implementation returns `false`.
        static func compatibleWithDiscoveryConfig(config: OPA.Config) -> Bool
    }

    /// HTTPBundleLoader is a slightly more specialized protocol to allow greater
    /// control for HTTP-based bundle loaders.
    public protocol HTTPBundleLoader: BundleLoader {
        /// Needs a public constructor that can build from the config directly.
        init(
            config: OPA.Config,
            bundleResourceName: String,
            etag: String?,
            headers: [String: String]?,
            httpClientConfig: HTTPClient.Configuration?) throws

        /// Constructor for loading a discovery bundle over HTTP.
        ///
        /// The loader should read the bundle location from `config.discovery`
        /// rather than `config.bundles`. Loaders that don't support discovery
        /// inherit a default implementation that throws.
        init(
            discoveryConfig: OPA.Config,
            etag: String?,
            headers: [String: String]?,
            httpClientConfig: HTTPClient.Configuration?) throws

        /// Used by the loader-managing task to determine whether to sleep or not between polls.
        func isLongPollingEnabled() -> Bool
    }
}

// MARK: - Default Discovery Implementations

extension OPA.BundleLoader {
    /// Default: this loader does not support discovery.
    public static func compatibleWithDiscoveryConfig(config: OPA.Config) -> Bool {
        return false
    }

    /// Default: loader throws at init time.
    public init(discoveryConfig: OPA.Config) throws {
        throw RuntimeError(code: .discoveryNotSupported, message: "Bundle loader does not support Discovery")
    }

}

extension OPA.HTTPBundleLoader {
    /// Default: loader throws at init time.
    public init(
        discoveryConfig: OPA.Config,
        etag: String?,
        headers: [String: String]?,
        httpClientConfig: HTTPClient.Configuration?
    ) throws {
        throw RuntimeError(code: .discoveryNotSupported, message: "Bundle loader does not support Discovery")
    }
}
