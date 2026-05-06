import Foundation
import Rego

extension OPA {
    // MARK: - OAuth2 Client Credentials Authentication Plugin

    /// Authentication via an OAuth2 access token obtained through the
    /// client credentials grant.
    ///
    /// The bundle client fetches an access token from the token endpoint
    /// by POSTing form-encoded credentials, then attaches the returned
    /// access token as a `Bearer` Authorization header on each bundle
    /// request. The token is cached per-loader and re-fetched when the
    /// cached token is within
    /// ``tokenRefreshLeewaySeconds`` of expiry.
    ///
    /// This is the "basic" form. Advanced mechanisms supported by OPA's
    /// Go plugin (JWT assertions, AWS KMS signing, Azure Key Vault,
    /// client assertions, `signing_key`, `jwt_bearer` grant type) are
    /// deliberately unsupported here and will be rejected by
    /// ``validate()``.
    // From: v1/plugins/rest/auth.go (oauth2ClientCredentialsAuthPlugin)
    public struct OAuth2ClientCredentialsPlugin: Codable, Sendable, Equatable {
        /// OAuth2 token endpoint URL. Must use `https://`.
        public let tokenURL: String
        /// OAuth2 client identifier.
        public let clientID: String
        /// OAuth2 client secret. Sent via HTTP Basic Auth on the token request.
        public let clientSecret: String
        /// Grant type. Only `"client_credentials"` is supported at present.
        public let grantType: String
        /// Optional OAuth2 scopes. Space-joined and sent as the `scope`
        /// form parameter on the token request.
        public let scopes: [String]?
        /// Optional extra HTTP headers added to the token request.
        public let additionalHeaders: [String: String]?
        /// Optional extra form parameters added to the token request body.
        public let additionalParameters: [String: String]?

        /// Seconds of remaining token lifetime, below which the cached
        /// token is considered stale and a refresh is triggered on the
        /// next bundle request. Matches `minTokenLifetime` in the Go
        /// plugin (`v1/plugins/rest/auth.go`).
        public static let tokenRefreshLeewaySeconds: Double = 10

        public init(
            tokenURL: String,
            clientID: String,
            clientSecret: String,
            grantType: String = "client_credentials",
            scopes: [String]? = nil,
            additionalHeaders: [String: String]? = nil,
            additionalParameters: [String: String]? = nil
        ) throws {
            self.tokenURL = tokenURL
            self.clientID = clientID
            self.clientSecret = clientSecret
            self.grantType = grantType
            self.scopes = scopes
            self.additionalHeaders = additionalHeaders
            self.additionalParameters = additionalParameters
            try self.validate()
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.tokenURL = try container.decode(String.self, forKey: .tokenURL)
            self.clientID = try container.decode(String.self, forKey: .clientID)
            self.clientSecret = try container.decode(String.self, forKey: .clientSecret)
            self.grantType =
                try container.decodeIfPresent(String.self, forKey: .grantType) ?? "client_credentials"
            self.scopes = try container.decodeIfPresent([String].self, forKey: .scopes)
            self.additionalHeaders = try container.decodeIfPresent(
                [String: String].self, forKey: .additionalHeaders)
            self.additionalParameters = try container.decodeIfPresent(
                [String: String].self, forKey: .additionalParameters)
            try self.validate()
        }

        /// Validates struct-local constraints.
        public func validate() throws {
            guard !tokenURL.isEmpty else {
                throw ConfigError(
                    code: .internalError,
                    message: "Invalid OAuth2 config: token_url must not be empty"
                )
            }
            // Matches the Go plugin's explicit https check
            // (`v1/plugins/rest/auth.go`: "token_url required to use https scheme").
            guard tokenURL.lowercased().hasPrefix("https://") else {
                throw ConfigError(
                    code: .internalError,
                    message: "Invalid OAuth2 config: token_url must use the https:// scheme"
                )
            }
            guard grantType == "client_credentials" else {
                throw ConfigError(
                    code: .internalError,
                    message:
                        "Invalid OAuth2 config: grant_type \"\(grantType)\" is not yet supported; only \"client_credentials\" is supported"
                )
            }
            guard !clientID.isEmpty else {
                throw ConfigError(
                    code: .internalError,
                    message: "Invalid OAuth2 config: client_id must not be empty"
                )
            }
            guard !clientSecret.isEmpty else {
                throw ConfigError(
                    code: .internalError,
                    message: "Invalid OAuth2 config: client_secret must not be empty"
                )
            }
        }

        private enum CodingKeys: String, CodingKey {
            case tokenURL = "token_url"
            case clientID = "client_id"
            case clientSecret = "client_secret"
            case grantType = "grant_type"
            case scopes
            case additionalHeaders = "additional_headers"
            case additionalParameters = "additional_parameters"
        }
    }
}
