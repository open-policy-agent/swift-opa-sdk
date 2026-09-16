import Config
import Logging
import Rego

extension OPA {
    /// Selects and constructs a ``BundleLoader`` for a bundle resource or for a
    /// discovery config, driven purely by each loader type's compatibility check.
    ///
    /// Extracted so the loader-selection policy (priority order plus the HTTP
    /// init that threads `headers`/`httpClientConfig`/`httpClientCache`) lives in
    /// one place. Reused by ``Runtime`` and ``DiscoveryConfigProvider``, and
    /// usable directly by callers building their own bundle management on top of
    /// the loaders without a ``Runtime``.
    public struct BundleLoaderFactory: Sendable {
        /// Loader types tried in priority order.
        public let loaderTypes: [BundleLoader.Type]
        /// Extra headers applied to every HTTP loader's requests.
        public let headers: [String: String]?
        /// Where HTTP loaders get their client configuration.
        public let httpClientConfig: OPA.HTTPClientConfigSource?
        /// Shared client cache for connection pooling across HTTP loaders.
        public let httpClientCache: OPA.HTTPClientCache?
        /// Logger passed to constructed loaders.
        public let logger: Logger

        public init(
            loaderTypes: [BundleLoader.Type],
            headers: [String: String]? = nil,
            httpClientConfig: OPA.HTTPClientConfigSource? = nil,
            httpClientCache: OPA.HTTPClientCache? = nil,
            logger: Logger? = nil
        ) {
            self.loaderTypes = loaderTypes
            self.headers = headers
            self.httpClientConfig = httpClientConfig
            self.httpClientCache = httpClientCache
            self.logger = logger ?? Logger(label: "swift-opa.bundle-loader-factory")
        }

        /// Builds a loader for the named bundle resource in `config`.
        ///
        /// HTTP-capable loaders are built through the HTTP initializer so the
        /// injected `headers`/`httpClientConfig`/`httpClientCache` reach them.
        public func makeLoader(name: String, config: OPA.Config) throws -> any OPA.BundleLoader {
            try selectAndBuild(
                compatible: { $0.compatibleWithConfig(config: config, bundleResourceName: name) },
                buildHTTP: {
                    try $0.init(
                        config: config, bundleResourceName: name, etag: nil, headers: headers,
                        httpClientConfig: httpClientConfig, httpClientCache: httpClientCache, logger: logger)
                },
                buildBasic: { try $0.init(config: config, bundleResourceName: name, logger: logger) },
                notFoundMessage: "Unsupported bundle source for bundle \(name)")
        }

        /// Builds a loader for the discovery bundle described by `config.discovery`.
        public func makeDiscoveryLoader(config: OPA.Config) throws -> any OPA.BundleLoader {
            try selectAndBuild(
                compatible: { $0.compatibleWithDiscoveryConfig(config: config) },
                buildHTTP: {
                    try $0.init(
                        discoveryConfig: config, etag: nil, headers: headers,
                        httpClientConfig: httpClientConfig, httpClientCache: httpClientCache, logger: logger)
                },
                buildBasic: { try $0.init(discoveryConfig: config, logger: logger) },
                notFoundMessage: "No compatible bundle loader found for discovery configuration")
        }

        /// Shared selection: returns the first loader type that passes
        /// `compatible`, built via `buildHTTP` when it is an ``OPA/HTTPBundleLoader``
        /// or `buildBasic` otherwise. Throws with `notFoundMessage` if none match.
        private func selectAndBuild(
            compatible: (BundleLoader.Type) -> Bool,
            buildHTTP: (any OPA.HTTPBundleLoader.Type) throws -> any OPA.BundleLoader,
            buildBasic: (BundleLoader.Type) throws -> any OPA.BundleLoader,
            notFoundMessage: @autoclosure () -> String
        ) throws -> any OPA.BundleLoader {
            for loaderType in loaderTypes where compatible(loaderType) {
                if let httpLoaderType = loaderType as? any OPA.HTTPBundleLoader.Type {
                    return try buildHTTP(httpLoaderType)
                }
                return try buildBasic(loaderType)
            }
            throw RuntimeError(code: .internalError, message: notFoundMessage())
        }
    }
}
