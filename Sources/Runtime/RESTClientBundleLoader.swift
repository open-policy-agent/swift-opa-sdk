import AsyncHTTPClient
import Config
import Foundation
import NIOCore  // Needed for type TimeAmount
import NIOHTTP1  // Needed for type HTTPHeaders
import Rego

extension OPA {
    /// RESTClientBundleLoader abstracts over OPA's HTTP-based bundle sources.
    /// It supports both [`ETag` bundle caching][bundle-caching], and
    /// [HTTP long-polling][bundle-long-polling].
    ///
    /// ## `ETag` Bundle Caching
    ///
    /// When a bundle is successfully fetched and parsed from the bundle
    /// server, the loader will cache both the parsed bundle and any `ETag`
    /// header value that was provided in the server's response. This
    /// ETag value is then sent in the `ETag` header on future requests.
    ///
    /// If the server returns a `304 Not Modified` response, the loader
    /// will return the last successfully parsed bundle from the cache.
    ///
    /// The ETag value is only updated when a new bundle is successfully
    /// fetched, which allows the remote server to avoid sending the same
    /// bundle over the wire on each polling attempt.
    ///
    /// ## HTTP Long-Polling Support
    ///
    /// The loader provides a `Prefer` header to the bundle server on each
    /// request, including an optional `wait` parameter in the header value
    /// if the bundle resource configuration includes a non-zero
    /// `polling.long_polling_timeout_seconds` value.
    ///
    /// If the server supports long-polling, it will reply with a special
    /// `Content-Type` header. The loader checks every server response for
    /// this header value, and when detected, enables long-polling for the
    /// next request.
    ///
    /// The server then will hold the connection open for up to the duration
    /// in seconds specified in the `Prefer` header's `wait` parameter, and
    /// then will reply with either a bundle, the `304 Not Modified`
    /// response, or an error.
    ///
    /// The `OPA.Runtime` can inspect `HTTPBundleLoader` types like this one
    /// to see if long-polling has been enabled, and will disable the normal
    /// polling delays derived from the `polling.min_delay_seconds` and
    /// `polling.max_delay_seconds` OPA config fields (because it assumes
    /// that the loader has already waited some duration from the mechanics
    /// of normal long-polling).
    ///
    /// If the server ever stops returning the special `Content-Type` header
    /// in its responses, the loader will automatically disable long-polling,
    /// and will switch back to normal polling.
    ///
    /// ## Limitations
    ///
    /// - Bundle persistence for downloaded bundles is not yet implemented.
    /// - Bundle signature verification is not yet implemented.
    ///
    ///    [bundle-caching]: https://www.openpolicyagent.org/docs/management-bundles#caching
    ///    [bundle-long-polling]: https://www.openpolicyagent.org/docs/management-bundles#http-long-polling
    public struct RESTClientBundleLoader: HTTPBundleLoader, BundleLoader {
        /// The `bundle` resource name from the config.
        public let name: String

        /// The file URL of the folder or tarball on disk.
        public let fetchURL: URL

        /// `ETag` HTTP header value from the last successfully fetched/parsed bundle.
        public private(set) var etag: String

        /// Control plane service config used.
        public let serviceConfig: ServiceConfig

        /// Bundle resource config used.
        public let bundleConfig: BundleSourceConfig

        /// A dictionary of custom header key/value pairs that will be
        /// set on each request.
        ///
        /// Note: These headers are set *before* credentials handlers,
        /// `ETag` caching, and long-polling headers are applied. Any
        /// conflicting header values will be overwritten.
        public let customHeaders: [String: String]

        /// HTTPClient configuration to use when polling.
        public private(set) var httpClientConfig: HTTPClient.Configuration

        /// Polling configuration.
        public let polling: PollingConfig?

        /// The cached instance of the last successfully fetched and parsed bundle.
        private var lastBundle: OPA.Bundle?

        /// A state flag for tracking whether the next request from this
        /// loader will be attempting a long-polling request or not.
        private var longPollingEnabled: Bool

        public init(
            config: OPA.Config,
            bundleResourceName: String
        ) throws {
            self = try Self.init(config: config, bundleResourceName: bundleResourceName, etag: nil)
        }

        public init(
            config: Rego.OPA.Config,
            bundleResourceName: String,
            etag: String? = nil,
            headers: [String: String]? = nil,
            httpClientConfig: HTTPClient.Configuration? = nil
        ) throws {
            guard let resource = config.bundles[bundleResourceName] else {
                throw RuntimeError(
                    code: .internalError,
                    message: "No bundle config was found for bundle resource \(bundleResourceName)."
                )
            }
            let name = bundleResourceName

            // Fail if no bundle service specified.
            guard !resource.service.isEmpty else {
                throw RuntimeError(
                    code: .internalError,
                    message: "No service config was provided for bundle config \(name)."
                )
            }

            // Fail if bundle service is not found in the config.
            guard let service = config.services[resource.service] else {
                throw RuntimeError(
                    code: .internalError,
                    message: "No service config was found for bundle config \(name)."
                )
            }

            self.name = name
            self.fetchURL = service.url.appending(path: resource.resource ?? "/bundle/\(name)")
            self.etag = etag ?? ""
            self.serviceConfig = service
            self.bundleConfig = resource
            self.customHeaders = headers ?? [:]
            let httpClientConfig = httpClientConfig ?? HTTPClient.Configuration.singletonConfiguration
            self.httpClientConfig = httpClientConfig
            self.polling = resource.downloaderConfig.polling
            self.lastBundle = nil
            self.longPollingEnabled = false
        }

        /// Constructor for loading from the `discovery` section of the config.
        public init(
            discoveryConfig config: OPA.Config
        ) throws {
            self = try Self.init(discoveryConfig: config, etag: nil)
        }

        public init(
            discoveryConfig config: OPA.Config,
            etag: String? = nil,
            headers: [String: String]? = nil,
            httpClientConfig: HTTPClient.Configuration? = nil
        ) throws {
            guard let discovery = config.discovery else {
                throw RuntimeError(
                    code: .internalError,
                    message: "No discovery config found."
                )
            }

            guard !discovery.service.isEmpty else {
                throw RuntimeError(
                    code: .internalError,
                    message: "No service config was provided for discovery."
                )
            }

            guard let service = config.services[discovery.service] else {
                throw RuntimeError(
                    code: .internalError,
                    message: "Service '\(discovery.service)' referenced by discovery config not found."
                )
            }

            self.name = "discovery"
            self.fetchURL = service.url.appending(
                path: discovery.resource)  // TODO: Should we default this to: "/bundles/discovery"?
            self.etag = etag ?? ""
            self.serviceConfig = service
            self.bundleConfig = try BundleSourceConfig(
                downloaderConfig: discovery.downloaderConfig,
                service: discovery.service,
                resource: discovery.resource,
                signing: discovery.signing
            )
            self.customHeaders = headers ?? [:]
            let httpClientConfig = httpClientConfig ?? HTTPClient.Configuration.singletonConfiguration
            self.httpClientConfig = httpClientConfig
            self.polling = discovery.downloaderConfig.polling
            self.lastBundle = nil
            self.longPollingEnabled = false
        }

        /// Compatibility check against the OPA bundle config section.
        /// If the resource is of a supported credential type, this check returns `true`.
        /// Currently, supported credential types are: (default no auth), Bearer auth, Client TLS auth.
        public static func compatibleWithConfig(config: Config, bundleResourceName: String) -> Bool {
            guard let resource = config.bundles[bundleResourceName] else {
                return false
            }

            let isFileURL = (URL(string: resource.resource ?? "")?.scheme == "file")
            guard !isFileURL && !resource.service.isEmpty else {
                return false  // Bail if no service referenced, or if it's a file URL.
            }

            guard let service = config.services[resource.service] else {
                return false
            }

            switch service.credentials {
            case .defaultNoAuth, .bearer(_), .clientTLS(_): return true
            // Other REST client types not implemented yet.
            default: return false
            }
        }

        /// Compatibility check against the OPA discovery config section.
        /// This check has the same constraints as the `compatibleWithConfig` check.
        public static func compatibleWithDiscoveryConfig(config: Config) -> Bool {
            guard let discovery = config.discovery else {
                return false
            }

            let isFileURL = (URL(string: discovery.resource)?.scheme == "file")
            guard !isFileURL && !discovery.service.isEmpty else {
                return false
            }

            guard let service = config.services[discovery.service] else {
                return false
            }

            switch service.credentials {
            case .defaultNoAuth, .bearer(_), .clientTLS(_): return true
            default: return false
            }
        }

        /// Loads a bundle from the remote source, returning either a
        /// successfully parsed OPA bundle, or an error.
        ///
        /// This method adjusts request headers based on the credential type,
        /// `ETag` caching, and long-polling support of the bundle server.
        public mutating func load() async -> Result<OPA.Bundle, any Swift.Error> {
            let headers =
                (self.serviceConfig.headers ?? [:]).merging(
                    self.customHeaders, uniquingKeysWith: { (_, new) in new })

            var httpRequest = HTTPClientRequest(url: self.fetchURL.absoluteString)
            httpRequest.method = .GET
            for (k, v) in headers {
                httpRequest.headers.replaceOrAdd(name: k, value: v)
            }

            // Set authorization headers.
            switch self.serviceConfig.credentials {
            case .defaultNoAuth: break
            case .bearer(let pluginConfig):
                let loader: OPA.BearerAuthPluginLoader = BearerAuthPluginLoader(config: pluginConfig)
                do {
                    try loader.prepare(req: &httpRequest)
                } catch {
                    return .failure(error)
                }
            case .clientTLS(let pluginConfig):
                let loader = OPA.ClientTLSAuthPluginLoader(config: pluginConfig)
                do {
                    // prepare is a no-op for clientTLS, but keep the pattern symmetric.
                    try loader.prepare(req: &httpRequest)
                    // If the caller didn't pre-build an mTLS-aware httpClientConfig,
                    // build one here, mutating self.httpClientConfig if needed.
                    self.httpClientConfig = try loader.newHTTPClientConfig(
                        service: self.serviceConfig,
                        base: self.httpClientConfig
                    )
                } catch {
                    return .failure(error)
                }
            default:
                return .failure(
                    RuntimeError(
                        code: .internalError,
                        message: "Unsupported bundle service type used for bundle config \(name)."
                    ))
            }

            // Set If-None-Match header for ETag supporting servers.
            if !self.etag.isEmpty {
                httpRequest.headers.replaceOrAdd(name: "if-none-match", value: self.etag)
            }

            // Set preference/long-polling headers.
            // Future: Switch to the full "modes=snapshot,delta" when we support delta bundles.
            var prefHeader = "modes=snapshot"
            let usingLongPolling = self.longPollingEnabled && self.polling?.longPollingTimeoutSeconds != nil
            if usingLongPolling {
                prefHeader += ";wait=\(self.polling?.longPollingTimeoutSeconds ?? 0)"
            }
            httpRequest.headers.replaceOrAdd(name: "prefer", value: prefHeader)

            // Launch HTTP request, process response.
            do {
                var longPollingTA: Int64 = 0
                if let longPollTimeout = self.polling?.longPollingTimeoutSeconds, usingLongPolling {
                    longPollingTA = longPollTimeout
                }

                // Create a one-off HTTPClient, and shut it down when we're done.
                return try await HTTPClient.withHTTPClient(
                    eventLoopGroup: .singletonMultiThreadedEventLoopGroup,
                    configuration: self.httpClientConfig,
                    backgroundActivityLogger: nil,
                    { httpClient in
                        let response =
                            if longPollingTA > 0 {
                                try await httpClient.execute(httpRequest, timeout: .seconds(longPollingTA))
                            } else {
                                try await httpClient.execute(httpRequest, deadline: NIODeadline.distantFuture)
                            }
                        // Future: Add logger warning if Content-Type header values are off. (Validation done by OPA)

                        // Collect the full response body into a ByteBuffer.
                        let maxBytesLimit = 50 * 1024 * 1024  // 50 MB
                        let body = try await response.body.collect(upTo: maxBytesLimit)

                        if response.status.code == 304 {
                            guard let bundle = self.lastBundle else {
                                return Result<OPA.Bundle, Error>.failure(
                                    RuntimeError(
                                        code: .internalError,
                                        message:
                                            "Bundle download failed. Server returned response code 304 Not Modified, but no prior bundle cached."
                                    ))
                            }
                            return .success(bundle)
                            // Otherwise, fall through to error handler.
                        }

                        guard (200..<300).contains(response.status.code) else {
                            throw RuntimeError(
                                code: .internalError,
                                message: "Bundle download failed with response code: \(response.status.code)")
                        }

                        // Convert ByteBuffer to Data.
                        let data = Data(body.readableBytesView)

                        // Decode the tarball into an OPA.Bundle.
                        let newBundle = try OPA.Bundle.decodeFromTarball(from: data)

                        // Cache last bundle, so we can handle the "no changes case".
                        self.lastBundle = newBundle
                        self.etag = response.headers["etag"].first ?? ""
                        self.longPollingEnabled = isLongPollingSupported(headers: response.headers)
                        return .success(newBundle)
                    })
            } catch {
                self.etag = ""
                return .failure(error)
            }
        }

        /// Utility function to see if the last response's headers indicate the server supports long-polling.
        private func isLongPollingSupported(headers: HTTPHeaders) -> Bool {
            return headers["content-type"].contains("application/vnd.openpolicyagent.bundles")
        }

        public func isLongPollingEnabled() -> Bool {
            return self.longPollingEnabled
        }
    }

    /// Emulates the same basic functionality as the `rest.bearerAuthPlugin` type from OPA.
    public struct BearerAuthPluginLoader {
        public let config: BearerAuthPlugin

        public init(config: BearerAuthPlugin) {
            self.config = config
        }

        public func prepare(req: inout HTTPClientRequest) throws {
            // Either a token was provided in the config, or we have a tokenPath to fetch the token from.
            var token = self.config.token ?? ""
            if let path = self.config.tokenPath, token.isEmpty {
                let url = URL(
                    filePath: path, directoryHint: .inferFromPath,
                    relativeTo: URL(fileURLWithPath: FileManager.default.currentDirectoryPath))
                token = try String(contentsOf: url, encoding: .utf8).trimmingCharacters(in: .whitespaces)
            }

            token = (self.config.encode) ? Data(token.utf8).base64EncodedString() : token

            req.headers.replaceOrAdd(name: "authorization", value: "\(self.config.scheme) \(token)")
        }
    }
}
