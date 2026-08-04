import AsyncHTTPClient
import Config
import Foundation
import Logging
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
    /// ## OPA IR Bundle Content Negotiation
    ///
    /// Every request sends an `Accept` header with a q-weighted list of
    /// the bundle media types this loader can consume, ordered by preference:
    /// the OPA IR bundle type first, then the OPA bundle type, then plain
    /// gzip, and finally `*/*` as a catch-all.
    ///
    /// The `Accept` default is applied *before* the service config and
    /// custom headers are merged in, so it can be overridden per-service.
    ///
    /// ## Limitations
    ///
    /// - Bundle persistence for downloaded bundles is not yet implemented.
    /// - Bundle signature verification is not yet implemented.
    ///
    ///    [bundle-caching]: https://www.openpolicyagent.org/docs/management-bundles#caching
    ///    [bundle-long-polling]: https://www.openpolicyagent.org/docs/management-bundles#http-long-polling
    public struct RESTClientBundleLoader: HTTPBundleLoader, BundleLoader {
        /// The `Accept` header value sent on every HTTP bundle request.
        public static let defaultAcceptHeader =
            [
                "application/vnd.openpolicyagent.bundle.ir.v1+gzip;q=1.0",
                "application/vnd.openpolicyagent.bundles;q=0.9",
                "application/gzip;q=0.8",
                "*/*;q=0.1",
            ].joined(separator: ", ")

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
        ///
        /// They are, however, applied *after* the default `Accept` header,
        /// so a custom or service-config `Accept` value wins.
        public let customHeaders: [String: String]

        /// The `HTTPClient.Configuration` used by the most recent `load()`.
        /// Before the first load it holds the baseline derived from the source.
        public private(set) var httpClientConfig: HTTPClient.Configuration

        private let httpClientConfigSource: HTTPClientConfigSource?

        /// Polling configuration.
        public let polling: PollingConfig?

        /// The cached instance of the last successfully fetched and parsed bundle.
        private var lastBundle: OPA.Bundle?

        /// A state flag for tracking whether the next request from this
        /// loader will be attempting a long-polling request or not.
        private var longPollingEnabled: Bool

        private var logger: Logger

        /// Credential-type dispatch. Built once from the service's
        /// credentials at init time and reused by every `load()` call so
        /// per-loader caches (the client-TLS cert cache, the OAuth2
        /// token cache) actually persist.
        private enum CredentialLoader: Sendable {
            case defaultNoAuth
            case bearer(BearerAuthPluginLoader)
            case clientTLS(ClientTLSAuthPluginLoader)
            case oauth2(OAuth2ClientCredentialsPluginLoader)
        }

        private let credentialLoader: CredentialLoader

        private var clientTLSLoader: ClientTLSAuthPluginLoader? {
            guard case .clientTLS(let loader) = self.credentialLoader else { return nil }
            return loader
        }

        /// Static because `init` cannot read a computed property before every
        /// stored property is initialized.
        private static func baselineHTTPClientConfig(
            for source: HTTPClientConfigSource?
        ) -> HTTPClient.Configuration {
            guard case .fixed(let injected) = source else {
                return HTTPClient.Configuration.singletonConfiguration
            }
            return injected
        }

        /// Joins a service base URL with a resource string that may contain
        /// a query string or fragment.
        ///
        /// We had bugs in URL handling previously from using just
        /// `URL.appending(path:)`, because it treats its argument as a
        /// literal path component and percent-encodes reserved characters
        /// like `?` and `#`. That breaks resources of the form
        /// `example?foo=bar`, which turn into `.../example%3Ffoo=bar`.
        ///
        /// Here we split off the query/fragment tail before appending, then
        /// attach it as a raw suffix.
        private static func buildFetchURL(baseURL: URL, resource: String) -> URL {
            guard let splitIdx = resource.firstIndex(where: { $0 == "?" || $0 == "#" }) else {
                return baseURL.appending(path: resource)
            }
            let pathPart = String(resource[..<splitIdx])
            let queryAndFragment = String(resource[splitIdx...])
            let withPath = baseURL.appending(path: pathPart)
            return URL(string: withPath.absoluteString + queryAndFragment) ?? withPath
        }

        /// Builds the credential loader for a service's credentials. Fails
        /// for credential types the REST client doesn't yet support, so
        /// misconfigurations surface at init time rather than at the
        /// first `load()`.
        private static func buildCredentialLoader(
            credentials: ServiceConfig.Credentials?,
            bundleName: String
        ) throws -> CredentialLoader {
            switch credentials {
            case .none, .defaultNoAuth:
                return .defaultNoAuth
            case .bearer(let cfg):
                return .bearer(BearerAuthPluginLoader(config: cfg))
            case .clientTLS(let cfg):
                return .clientTLS(ClientTLSAuthPluginLoader(config: cfg))
            case .oauth2(let cfg):
                return .oauth2(OAuth2ClientCredentialsPluginLoader(config: cfg))
            default:
                throw RuntimeError(
                    code: .internalError,
                    message: "Unsupported bundle service credential type used for bundle config \(bundleName)."
                )
            }
        }

        public init(
            config: OPA.Config,
            bundleResourceName: String,
            logger: Logger? = nil
        ) throws {
            self = try Self.init(config: config, bundleResourceName: bundleResourceName, etag: nil, logger: logger)
        }

        public init(
            config: Rego.OPA.Config,
            bundleResourceName: String,
            etag: String? = nil,
            headers: [String: String]? = nil,
            httpClientConfig: HTTPClientConfigSource? = nil,
            logger: Logger? = nil
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
            self.fetchURL = Self.buildFetchURL(
                baseURL: service.url, resource: resource.resource ?? "/bundle/\(name)")
            self.etag = etag ?? ""
            self.serviceConfig = service
            self.bundleConfig = resource
            self.customHeaders = headers ?? [:]
            self.httpClientConfigSource = httpClientConfig
            self.httpClientConfig = Self.baselineHTTPClientConfig(for: httpClientConfig)
            self.polling = resource.downloaderConfig.polling
            self.lastBundle = nil
            self.longPollingEnabled = false
            self.logger = logger ?? Logger(label: "swift-opa.bundle.downloader")
            self.credentialLoader = try Self.buildCredentialLoader(
                credentials: service.credentials, bundleName: name)
            self.warnIfClientTLSCredentialIgnored()
        }

        /// Constructor for loading from the `discovery` section of the config.
        public init(
            discoveryConfig config: OPA.Config,
            logger: Logger? = nil
        ) throws {
            self = try Self.init(discoveryConfig: config, etag: nil, logger: logger)
        }

        public init(
            discoveryConfig config: OPA.Config,
            etag: String? = nil,
            headers: [String: String]? = nil,
            httpClientConfig: HTTPClientConfigSource? = nil,
            logger: Logger? = nil
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
            // TODO: Should we default this to: "/bundles/discovery"?
            self.fetchURL = Self.buildFetchURL(
                baseURL: service.url, resource: discovery.resource)
            self.etag = etag ?? ""
            self.serviceConfig = service
            self.bundleConfig = try BundleSourceConfig(
                downloaderConfig: discovery.downloaderConfig,
                service: discovery.service,
                resource: discovery.resource,
                signing: discovery.signing
            )
            self.customHeaders = headers ?? [:]
            self.httpClientConfigSource = httpClientConfig
            self.httpClientConfig = Self.baselineHTTPClientConfig(for: httpClientConfig)
            self.polling = discovery.downloaderConfig.polling
            self.lastBundle = nil
            self.longPollingEnabled = false
            self.logger = logger ?? Logger(label: "swift-opa.bundle.rest-client.discovery")
            self.credentialLoader = try Self.buildCredentialLoader(
                credentials: service.credentials, bundleName: "discovery")
            self.warnIfClientTLSCredentialIgnored()
        }

        /// Compatibility check against the OPA bundle config section.
        /// If the resource is of a supported credential type, this check returns `true`.
        /// Currently, supported credential types are: (default no auth), Bearer auth, Client TLS auth, OAuth2 client credentials.
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
            case .defaultNoAuth, .bearer(_), .clientTLS(_), .oauth2(_): return true
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
            case .defaultNoAuth, .bearer(_), .clientTLS(_), .oauth2(_): return true
            default: return false
            }
        }

        // MARK: - HTTP client configuration

        /// Resolves the `HTTPClient.Configuration` for a single `load()`,
        /// invoking the provider closure when the source carries one.
        private func buildActiveHTTPClientConfig() async throws -> HTTPClient.Configuration {
            switch self.httpClientConfigSource {
            case .none:
                guard let clientTLS = self.clientTLSLoader else {
                    return HTTPClient.Configuration.singletonConfiguration
                }
                return try clientTLS.newHTTPClientConfig(
                    service: self.serviceConfig, base: .singletonConfiguration)
            case .fixed(let injected):
                guard let clientTLS = self.clientTLSLoader else { return injected }
                return try clientTLS.newHTTPClientConfig(service: self.serviceConfig, base: injected)
            case .tls(let provider):
                var clientConfig = HTTPClient.Configuration.singletonConfiguration
                clientConfig.tlsConfiguration = try await provider()
                return clientConfig
            case .configuration(let provider):
                return try await provider()
            }
        }

        private func warnIfClientTLSCredentialIgnored() {
            guard let clientTLS = self.clientTLSLoader else { return }
            switch self.httpClientConfigSource {
            case .none, .fixed:
                return
            case .tls, .configuration:
                self.logger.warning(
                    """
                    Ignoring services['\(self.bundleConfig.service)'] credentials.client_tls: an \
                    httpClientConfig provider closure owns TLS for bundle '\(self.name)', so \
                    client_tls.cert=\(clientTLS.config.cert) is never read.
                    """
                )
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

            httpRequest.headers.replaceOrAdd(name: "accept", value: Self.defaultAcceptHeader)

            for (k, v) in headers {
                httpRequest.headers.replaceOrAdd(name: k, value: v)
            }

            // Config first, so a provider throw short-circuits before any
            // network I/O (an OAuth2 token request included).
            do {
                self.httpClientConfig = try await self.buildActiveHTTPClientConfig()
                try await self.prepareCredentials(req: &httpRequest)
            } catch {
                return .failure(error)
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
                        self.logger.debug("Attempting to fetch bundle from URL: \(self.fetchURL)")
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
                                message:
                                    "Bundle download on url \(self.fetchURL) failed with response code: \(response.status.code), body: \(String(buffer: body))"
                            )
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

        /// Applies the service's credential type to the outgoing request.
        private func prepareCredentials(req: inout HTTPClientRequest) async throws {
            switch self.credentialLoader {
            case .defaultNoAuth:
                break
            case .bearer(let loader):
                self.logger.info("Preparing bundle request with bearer authentication")
                try loader.prepare(req: &req)
            case .clientTLS(let loader):
                // A no-op for clientTLS; kept for symmetry.
                try loader.prepare(req: &req)
            case .oauth2(let loader):
                self.logger.debug("Preparing bundle request with OAuth2 client credentials authentication")
                try await loader.prepare(req: &req, service: self.serviceConfig, logger: self.logger)
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
    public struct BearerAuthPluginLoader: Sendable {
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
