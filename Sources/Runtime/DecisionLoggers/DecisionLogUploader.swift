import AsyncHTTPClient
import Config
import Foundation
import Logging
import NIOCore
import Rego
import SWCompression

extension OPA {
    /// Handles serializing, compressing, and uploading decision log events to a
    /// remote service. Shared by the buffered ``DecisionLogger`` implementations.
    ///
    /// The upload path mirrors ``OPA/RESTClientBundleLoader`` (auth reuse via the
    /// public credential plugin loaders, a pooled `HTTPClient` drawn from the
    /// shared ``OPA/HTTPClientCache`` keyed by service): events are chunked so
    /// each gzip-compressed payload stays within `upload_size_limit_bytes`, then
    /// POSTed as `Content-Encoding: gzip` JSON. When no cache is supplied (a
    /// standalone logger built without a `Runtime`), an ephemeral one-off client
    /// is created per request instead.
    public struct DecisionLogUploader: Sendable {
        private let service: OPA.ServiceConfig
        private let serviceName: String
        private let uploadURL: URL
        private let uploadSizeLimitBytes: Int
        private let baseHTTPClientConfig: HTTPClient.Configuration
        private let httpClientCache: OPA.HTTPClientCache?
        private let logger: Logger
        private let credentialLoader: CredentialLoader

        /// Credential-type dispatch, built once and reused so per-loader caches
        /// (OAuth2 token, client-TLS cert) persist. Mirrors the private enum in
        /// ``OPA/RESTClientBundleLoader``.
        private enum CredentialLoader: Sendable {
            case defaultNoAuth
            case bearer(BearerAuthPluginLoader)
            case clientTLS(ClientTLSAuthPluginLoader)
            case oauth2(OAuth2ClientCredentialsPluginLoader)
        }

        public init(
            service: OPA.ServiceConfig,
            serviceName: String,
            resource: String,
            uploadSizeLimitBytes: Int64,
            httpClientConfig: HTTPClient.Configuration?,
            httpClientCache: OPA.HTTPClientCache?,
            logger: Logger
        ) throws {
            self.service = service
            self.serviceName = serviceName
            self.uploadURL = Self.buildURL(baseURL: service.url, resource: resource)
            self.uploadSizeLimitBytes = Int(uploadSizeLimitBytes)
            let base = httpClientConfig ?? HTTPClient.Configuration.singletonConfiguration
            self.baseHTTPClientConfig = base
            self.httpClientCache = httpClientCache
            self.logger = logger
            self.credentialLoader = try Self.buildCredentialLoader(credentials: service.credentials)
        }

        /// Uploads the given events, chunked so each compressed payload fits
        /// under the configured size limit. Throws on the first failed POST so
        /// the caller can re-buffer and retry.
        public func upload(_ events: [OPA.DecisionLogEvent]) async throws {
            guard !events.isEmpty else { return }
            let chunks = try encodeChunks(events)
            for chunk in chunks {
                try await post(chunk)
            }
        }

        // MARK: - Encoding / chunking

        private static let encoder: JSONEncoder = {
            let e = JSONEncoder()
            e.dateEncodingStrategy = .iso8601
            e.outputFormatting = [.sortedKeys]
            return e
        }()

        /// Encodes `events` into one or more gzip-compressed JSON arrays, each
        /// within `uploadSizeLimitBytes`. Individual events that exceed the
        /// limit on their own are dropped with a warning (matching OPA).
        func encodeChunks(_ events: [OPA.DecisionLogEvent]) throws -> [Data] {
            var chunks: [Data] = []
            var batch: [OPA.DecisionLogEvent] = []
            var lastGood: Data? = nil

            func compressed(_ evts: [OPA.DecisionLogEvent]) throws -> Data {
                let json = try Self.encoder.encode(evts)
                return try GzipArchive.archive(data: json)
            }

            for event in events {
                batch.append(event)
                let candidate = try compressed(batch)
                if candidate.count <= uploadSizeLimitBytes {
                    lastGood = candidate
                    continue
                }

                // Over the limit with this event included.
                if batch.count == 1 {
                    // A single event that won't fit — drop it.
                    logger.warning(
                        "dropping decision log event exceeding upload_size_limit_bytes (\(candidate.count) > \(uploadSizeLimitBytes))"
                    )
                    batch.removeAll()
                    lastGood = nil
                    continue
                }

                // Flush the batch without this event, then start a new batch.
                if let good = lastGood {
                    chunks.append(good)
                }
                batch = [event]
                let single = try compressed(batch)
                if single.count <= uploadSizeLimitBytes {
                    lastGood = single
                } else {
                    logger.warning(
                        "dropping decision log event exceeding upload_size_limit_bytes (\(single.count) > \(uploadSizeLimitBytes))"
                    )
                    batch.removeAll()
                    lastGood = nil
                }
            }

            if !batch.isEmpty, let good = lastGood {
                chunks.append(good)
            }
            return chunks
        }

        // MARK: - HTTP

        private func post(_ body: Data) async throws {
            var request = HTTPClientRequest(url: self.uploadURL.absoluteString)
            request.method = .POST

            // Service-level custom headers first, then the ones we require.
            for (k, v) in service.headers ?? [:] {
                request.headers.replaceOrAdd(name: k, value: v)
            }
            request.headers.replaceOrAdd(name: "content-type", value: "application/json")
            request.headers.replaceOrAdd(name: "content-encoding", value: "gzip")

            // Rebuild the effective client config from the immutable baseline
            // each call (mirrors RESTClientBundleLoader for client-TLS).
            var effectiveConfig = self.baseHTTPClientConfig
            switch self.credentialLoader {
            case .defaultNoAuth:
                break
            case .bearer(let loader):
                try loader.prepare(req: &request)
            case .clientTLS(let loader):
                try loader.prepare(req: &request)
                effectiveConfig = try loader.newHTTPClientConfig(
                    service: self.service, base: self.baseHTTPClientConfig)
            case .oauth2(let loader):
                try await loader.prepare(req: &request, service: self.service, logger: self.logger)
            }

            request.body = .bytes(ByteBuffer(bytes: body))

            // Reuse a warm, pooled HTTPClient from the cache when one is
            // present, otherwise fall back to a one-off client for this request.
            try await OPA.HTTPClientCache.withClient(
                cache: self.httpClientCache,
                service: self.serviceName,
                configuration: effectiveConfig,
                backgroundActivityLogger: nil
            ) { httpClient in
                self.logger.debug("Uploading decision logs to \(self.uploadURL)")
                let response = try await httpClient.execute(request, deadline: .distantFuture)
                let maxBytes = 1 * 1024 * 1024  // 1 MB is plenty for an error body.
                let responseBody = try await response.body.collect(upTo: maxBytes)
                guard (200..<300).contains(response.status.code) else {
                    throw RuntimeError(
                        code: .internalError,
                        message:
                            "Decision log upload to \(self.uploadURL) failed with response code "
                            + "\(response.status.code), body: \(String(buffer: responseBody))"
                    )
                }
            }
        }

        // MARK: - Helpers

        /// Joins a service base URL with a resource string that may contain a
        /// query or fragment. Mirrors `RESTClientBundleLoader.buildFetchURL`.
        static func buildURL(baseURL: URL, resource: String) -> URL {
            guard let splitIdx = resource.firstIndex(where: { $0 == "?" || $0 == "#" }) else {
                return baseURL.appending(path: resource)
            }
            let pathPart = String(resource[..<splitIdx])
            let queryAndFragment = String(resource[splitIdx...])
            let withPath = baseURL.appending(path: pathPart)
            return URL(string: withPath.absoluteString + queryAndFragment) ?? withPath
        }

        private static func buildCredentialLoader(
            credentials: ServiceConfig.Credentials?
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
                    message: "Unsupported service credential type for decision log uploads."
                )
            }
        }
    }
}
