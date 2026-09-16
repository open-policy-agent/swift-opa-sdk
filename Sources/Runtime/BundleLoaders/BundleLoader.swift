import AST
import AsyncHTTPClient
import Config
import Foundation
import Logging
import Rego

extension OPA {

    /// BundleLoader abstracts over the details of retrieving a bundle.
    public protocol BundleLoader: Sendable {
        /// Needs a public constructor that can build from the config directly.
        init(config: OPA.Config, bundleResourceName: String, logger: Logger?) throws

        /// Constructor for loading a discovery bundle.
        ///
        /// The loader should read the bundle location from `config.discovery`
        /// rather than `config.bundles`. Loaders that don't support discovery
        /// inherit a default implementation that throws.
        init(discoveryConfig: OPA.Config, logger: Logger?) throws

        /// Load the bundle, based on the config and any existing state.
        mutating func load() async -> Result<OPA.Bundle, any Swift.Error>

        /// The polling window this loader should honor between loads. Returns
        /// nil to accept the default window. Defaulted to nil.
        var pollingConfig: OPA.PollingConfig? { get }

        /// Owns this loader's polling loop, reporting each poll to `sink` until
        /// the enclosing `Task` is cancelled. Defaulted to a loop that repeatedly
        /// calls ``load()``, so most loaders never implement it directly.
        mutating func run(name: String, into sink: @escaping OPA.BundleUpdateSink) async

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
            httpClientConfig: OPA.HTTPClientConfigSource?,
            httpClientCache: OPA.HTTPClientCache?,
            logger: Logger?) throws

        /// Constructor for loading a discovery bundle over HTTP.
        ///
        /// The loader should read the bundle location from `config.discovery`
        /// rather than `config.bundles`. Loaders that don't support discovery
        /// inherit a default implementation that throws.
        init(
            discoveryConfig: OPA.Config,
            etag: String?,
            headers: [String: String]?,
            httpClientConfig: OPA.HTTPClientConfigSource?,
            httpClientCache: OPA.HTTPClientCache?,
            logger: Logger?) throws

        /// Used by the loader-managing task to determine whether to sleep or not between polls.
        func isLongPollingEnabled() -> Bool
    }
}

// MARK: - Default Polling Loop

extension OPA.BundleLoader {
    /// Default: no loader-specific polling window.
    public var pollingConfig: OPA.PollingConfig? { nil }

    /// Default self-driving loop: repeatedly ``load()`` and report to `sink`,
    /// honoring long-polling and the loader's polling window, until cancelled.
    public mutating func run(name: String, into sink: @escaping OPA.BundleUpdateSink) async {
        await OPA.Polling.runBundleLoop(&self, name: name, into: sink)
    }
}

// MARK: - Default Discovery Implementations

extension OPA.BundleLoader {
    /// Default: this loader does not support discovery.
    public static func compatibleWithDiscoveryConfig(config: OPA.Config) -> Bool {
        return false
    }

    /// Default: loader throws at init time.
    public init(discoveryConfig: OPA.Config, logger: Logger?) throws {
        throw RuntimeError(code: .discoveryNotSupported, message: "Bundle loader does not support Discovery")
    }

}

extension OPA.HTTPBundleLoader {
    /// Default: loader throws at init time.
    public init(
        discoveryConfig: OPA.Config,
        etag: String?,
        headers: [String: String]?,
        httpClientConfig: OPA.HTTPClientConfigSource?,
        httpClientCache: OPA.HTTPClientCache?,
        logger: Logger?
    ) throws {
        throw RuntimeError(code: .discoveryNotSupported, message: "Bundle loader does not support Discovery")
    }
}
