import AsyncHTTPClient
import Config
import Foundation
import Logging
import NIOConcurrencyHelpers  // Needed for type NIOLockedValueBox
import NIOCore
import NIOHTTP1
import NIOSSL
import Rego

extension OPA {
    /// Emulates the basic client-credentials form of the
    /// `rest.oauth2ClientCredentialsAuthPlugin` type from OPA.
    ///
    /// `prepare` attaches `Authorization: Bearer <token>` to bundle
    /// requests, fetching a fresh access token from the configured
    /// `token_url` when the cached token is missing or within
    /// ``OAuth2ClientCredentialsPlugin/tokenRefreshLeewaySeconds`` of
    /// expiry. The token cache is held in a `NIOLockedValueBox` so
    /// this struct stays `Sendable` and value-typed while still
    /// persisting state across calls.
    public struct OAuth2ClientCredentialsPluginLoader: Sendable {
        public let config: OAuth2ClientCredentialsPlugin

        private struct CachedToken: Sendable {
            let token: String
            let expiresAt: Date
        }

        /// Cached access token shared across copies of the value-typed
        /// loader via `NIOLockedValueBox`.
        private let tokenCache = NIOLockedValueBox<CachedToken?>(nil)

        public init(config: OAuth2ClientCredentialsPlugin) {
            self.config = config
        }

        /// Attaches `Authorization: Bearer <token>` to `req`, refreshing
        /// the cached token from the OAuth2 token endpoint if needed.
        public func prepare(
            req: inout HTTPClientRequest,
            service: ServiceConfig,
            logger: Logger
        ) async throws {
            let token = try await ensureFreshToken(service: service, logger: logger)
            req.headers.replaceOrAdd(name: "authorization", value: "Bearer \(token)")
        }

        private func ensureFreshToken(service: ServiceConfig, logger: Logger) async throws -> String {
            let leeway = OAuth2ClientCredentialsPlugin.tokenRefreshLeewaySeconds
            if let cached = tokenCache.withLockedValue({ $0 }),
                cached.expiresAt.timeIntervalSinceNow > leeway
            {
                return cached.token
            }
            logger.debug("Requesting OAuth2 token from \(config.tokenURL)")
            let fresh = try await fetchToken(service: service)
            tokenCache.withLockedValue { $0 = fresh }
            return fresh.token
        }

        // MARK: - Token fetch

        /// Timeout for the token endpoint HTTP request (matches the Go
        /// plugin's hardcoded parameters).
        private static let tokenRequestTimeoutSeconds: Int64 = 10

        private func fetchToken(service: ServiceConfig) async throws -> CachedToken {
            // Build form-url-encoded body.
            // Order: start with additionalParameters, then overlay the
            // standard fields so additionalParameters can't override
            // grant_type / scope.
            var components = URLComponents()
            var items: [URLQueryItem] = []
            if let extra = config.additionalParameters {
                for (k, v) in extra { items.append(URLQueryItem(name: k, value: v)) }
            }
            items.append(URLQueryItem(name: "grant_type", value: "client_credentials"))
            if let scopes = config.scopes, !scopes.isEmpty {
                items.append(URLQueryItem(name: "scope", value: scopes.joined(separator: " ")))
            }
            components.queryItems = items
            let body = components.percentEncodedQuery ?? ""

            var request = HTTPClientRequest(url: config.tokenURL)
            request.method = .POST
            request.headers.replaceOrAdd(name: "content-type", value: "application/x-www-form-urlencoded")
            request.headers.replaceOrAdd(name: "accept", value: "application/json")

            // HTTP Basic Auth with client_id:client_secret.
            let basic = Data("\(config.clientID):\(config.clientSecret)".utf8).base64EncodedString()
            request.headers.replaceOrAdd(name: "authorization", value: "Basic \(basic)")

            // Set user-supplied additionalHeaders. Any attempt to set the
            // Authorization header will be overridden by the bundle loader
            // code later on.
            if let extra = config.additionalHeaders {
                for (k, v) in extra {
                    if k.lowercased() == "authorization" { continue }
                    request.headers.replaceOrAdd(name: k, value: v)
                }
            }

            request.body = .bytes(ByteBuffer(string: body))

            // Build a one-off HTTPClient for the token request,
            // inheriting allow_insecure_tls from the parent service.
            var tls = TLSConfiguration.makeClientConfiguration()
            tls.minimumTLSVersion = .tlsv12
            if service.allowInsecureTLS == true {
                tls.certificateVerification = .none
            }
            var clientConfig = HTTPClient.Configuration.singletonConfiguration
            clientConfig.tlsConfiguration = tls

            let deadline: NIODeadline = .now() + .seconds(Self.tokenRequestTimeoutSeconds)

            return try await HTTPClient.withHTTPClient(
                eventLoopGroup: .singletonMultiThreadedEventLoopGroup,
                configuration: clientConfig,
                backgroundActivityLogger: nil
            ) { client in
                let response = try await client.execute(request, deadline: deadline)
                let maxBytes = 1 * 1024 * 1024  // 1 MB max size for token response.
                let buffer = try await response.body.collect(upTo: maxBytes)

                guard (200..<300).contains(response.status.code) else {
                    throw RuntimeError(
                        code: .internalError,
                        message:
                            "OAuth2 token endpoint returned \(response.status.code): \(String(buffer: buffer))"
                    )
                }

                let decoded: TokenEndpointResponse
                do {
                    decoded = try JSONDecoder().decode(
                        TokenEndpointResponse.self, from: Data(buffer.readableBytesView))
                } catch {
                    throw RuntimeError(
                        code: .internalError,
                        message: "Failed to decode OAuth2 token endpoint response: \(error)",
                        cause: error
                    )
                }

                // Reject anything other than a bearer token. (Mirrors Go plugin behavior.)
                guard decoded.tokenType.lowercased() == "bearer" else {
                    throw RuntimeError(
                        code: .internalError,
                        message:
                            "OAuth2 token endpoint returned unsupported token_type: \(decoded.tokenType)"
                    )
                }

                let token = decoded.accessToken.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !token.isEmpty else {
                    throw RuntimeError(
                        code: .internalError,
                        message: "OAuth2 token endpoint returned an empty access_token"
                    )
                }

                return CachedToken(
                    token: token,
                    expiresAt: Date().addingTimeInterval(TimeInterval(decoded.expiresIn))
                )
            }
        }
    }
}

// MARK: - Token response decoding

/// Ported from Go's `tokenEndpointResponse` in `v1/plugins/rest/auth.go`.
private struct TokenEndpointResponse: Decodable {
    let accessToken: String
    let tokenType: String
    let expiresIn: Int64

    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
    }
}
