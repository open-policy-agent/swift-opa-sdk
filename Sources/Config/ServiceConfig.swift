// This file contains struct definitions for parsing the
// `services` section of an OPA configuration file.
// See: https://www.openpolicyagent.org/docs/configuration#services
import Foundation
import Rego

extension OPA {
    // MARK: - REST Client Service Configuration

    /// Configuration for a REST client service
    // From: v1/plugins/rest/rest.go
    public struct ServiceConfig: Codable, Equatable, Sendable {
        public let name: String?
        public let url: URL
        public let headers: [String: String]?
        public let allowInsecureTLS: Bool?
        public let responseHeaderTimeoutSeconds: Int64?
        public let tls: ServerTLSConfig?
        public let credentials: Credentials?
        public let type: String?

        private enum CodingKeys: String, CodingKey {
            case name
            case url
            case headers
            case allowInsecureTLS = "allow_insecure_tls"
            case responseHeaderTimeoutSeconds = "response_header_timeout_seconds"
            case tls
            case credentials
            case type
        }

        public init(
            name: String? = nil,
            url: URL,
            headers: [String: String]? = nil,
            allowInsecureTLS: Bool? = nil,
            responseHeaderTimeoutSeconds: Int64? = nil,
            tls: ServerTLSConfig? = nil,
            credentials: Credentials? = nil,
            type: String? = nil
        ) throws {
            self.name = name
            self.url = url
            self.headers = headers
            self.allowInsecureTLS = allowInsecureTLS
            self.responseHeaderTimeoutSeconds = responseHeaderTimeoutSeconds
            self.tls = tls
            let credentials = credentials ?? .defaultNoAuth
            self.type = type

            if case .bearer(let plugin) = credentials {
                self.credentials = try .bearer(plugin.resolved(serviceType: self.type))
            } else {
                self.credentials = credentials
            }

            try self.validate()
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.name = try container.decodeIfPresent(String.self, forKey: .name)
            self.url = try container.decode(URL.self, forKey: .url)
            self.headers = try container.decodeIfPresent([String: String].self, forKey: .headers)
            self.allowInsecureTLS = try container.decodeIfPresent(Bool.self, forKey: .allowInsecureTLS)
            self.responseHeaderTimeoutSeconds = try container.decodeIfPresent(
                Int64.self, forKey: .responseHeaderTimeoutSeconds)
            self.tls = try container.decodeIfPresent(ServerTLSConfig.self, forKey: .tls)
            let credentials = try container.decodeIfPresent(Credentials.self, forKey: .credentials) ?? .defaultNoAuth
            self.type = try container.decodeIfPresent(String.self, forKey: .type)

            if case .bearer(let plugin) = credentials {
                self.credentials = try .bearer(plugin.resolved(serviceType: self.type))
            } else {
                self.credentials = credentials
            }

            try self.validate()
        }

        // MARK: - Credentials (tagged union)

        /// Credentials represents the default set of REST client credential
        /// options supported by OPA for fetching bundles from remote sources.
        ///
        /// If a custom plugin name is provided, there won't be any associated
        /// config keys in this section-- any configuration will appear under the
        /// `plugins` section.
        public enum Credentials: Codable, Sendable, Equatable {
            case defaultNoAuth
            case bearer(BearerAuthPlugin)
            case oauth2(OAuth2ClientCredentialsPlugin)
            case clientTLS(ClientTLSAuthPlugin)
            case s3Signing([String: AnyCodable])
            case gcpMetadata(GCPMetadataAuthPlugin)
            case azureManagedIdentity(AzureManagedIdentitiesAuthPlugin)
            case custom(String)

            private enum CodingKeys: String, CodingKey {
                case bearer
                case oauth2
                case clientTLS = "client_tls"
                case s3Signing = "s3_signing"
                case gcpMetadata = "gcp_metadata"
                case azureManagedIdentity = "azure_managed_identity"
                case custom = "plugin"
            }

            public init(from decoder: Decoder) throws {
                let container = try decoder.container(keyedBy: CodingKeys.self)

                // Check if plugin field is present.
                if let pluginName = try container.decodeIfPresent(String.self, forKey: .custom) {
                    self = .custom(pluginName)
                    return
                }

                // Determine which credential keys are actually present in the payload.
                let credentialKeys: [CodingKeys] = [
                    .bearer, .oauth2, .clientTLS, .s3Signing, .gcpMetadata, .azureManagedIdentity,
                ]
                let presentKeys = credentialKeys.filter { container.contains($0) }

                guard presentKeys.count <= 1 else {
                    throw DecodingError.dataCorrupted(
                        DecodingError.Context(
                            codingPath: container.codingPath,
                            debugDescription:
                                "Expected at most one credential type, but found \(presentKeys.count)"
                        )
                    )
                }

                // No credential keys present (e.g. empty `{}`): default to no auth.
                guard let key = presentKeys.first else {
                    self = .defaultNoAuth
                    return
                }

                // Exactly one key present — decode it strictly so misconfigurations propagate.
                switch key {
                case .bearer:
                    self = .bearer(try container.decode(BearerAuthPlugin.self, forKey: .bearer))
                case .oauth2:
                    self = .oauth2(try container.decode(OAuth2ClientCredentialsPlugin.self, forKey: .oauth2))
                case .clientTLS:
                    self = .clientTLS(try container.decode(ClientTLSAuthPlugin.self, forKey: .clientTLS))
                case .s3Signing:
                    self = .s3Signing(try container.decode([String: AnyCodable].self, forKey: .s3Signing))
                case .gcpMetadata:
                    self = .gcpMetadata(try container.decode(GCPMetadataAuthPlugin.self, forKey: .gcpMetadata))
                case .azureManagedIdentity:
                    self = .azureManagedIdentity(
                        try container.decode(AzureManagedIdentitiesAuthPlugin.self, forKey: .azureManagedIdentity))
                default:
                    throw DecodingError.dataCorrupted(
                        DecodingError.Context(
                            codingPath: container.codingPath,
                            debugDescription: "Unexpected credential key: \(key.stringValue)"
                        )
                    )
                }
            }

            public func encode(to encoder: Encoder) throws {
                var container = encoder.container(keyedBy: CodingKeys.self)

                switch self {
                case .defaultNoAuth:
                    break
                case .bearer(let plugin):
                    try container.encode(plugin, forKey: .bearer)
                case .oauth2(let plugin):
                    try container.encode(plugin, forKey: .oauth2)
                case .clientTLS(let plugin):
                    try container.encode(plugin, forKey: .clientTLS)
                case .s3Signing(let config):
                    try container.encode(config, forKey: .s3Signing)
                case .gcpMetadata(let config):
                    try container.encode(config, forKey: .gcpMetadata)
                case .azureManagedIdentity(let config):
                    try container.encode(config, forKey: .azureManagedIdentity)
                case .custom(let plugin):
                    try container.encode(plugin, forKey: .custom)
                }
            }
        }

        // Validates struct-local constraints.
        public func validate() throws {
            // Ensure URL is a valid HTTP/HTTPS URL.
            guard let scheme = self.url.scheme?.lowercased(),
                scheme == "http" || scheme == "https",
                self.url.host != nil
            else {
                throw OPA.ConfigError(
                    code: .internalError, message: "Expected a valid http/https URL, got: \(self.url)")
            }

            // For credentials types that need extra context, we validate those here.
            switch self.credentials {
            case .clientTLS(let plugin):
                try plugin.validateWithContext(serviceTLS: self.tls)
            case .azureManagedIdentity(let plugin):
                try plugin.validateWithContext(serviceType: self.type ?? "")
            default:
                break
            }
        }
    }

    // MARK: - Server TLS Configuration

    // From: v1/plugins/rest/auth.go
    public struct ServerTLSConfig: Codable, Sendable, Equatable {
        public let caCert: String?
        public let systemCARequired: Bool?

        public init(
            caCert: String? = nil,
            systemCARequired: Bool? = nil
        ) {
            self.caCert = caCert
            self.systemCARequired = systemCARequired
        }

        private enum CodingKeys: String, CodingKey {
            case caCert = "ca_cert"
            case systemCARequired = "system_ca_required"
        }
    }

    // MARK: - AnyCodable Helper

    /// A type-erased Codable value.
    /// We should be able to remove this once we finish plumbing in Config types.
    public struct AnyCodable: Codable, Sendable, Equatable {
        public let value: Sendable

        public init(_ value: Sendable) {
            self.value = value
        }

        public static func == (lhs: AnyCodable, rhs: AnyCodable) -> Bool {
            switch lhs.value {
            case let bool as Bool:
                return bool == (rhs.value as? Bool)
            case let int as Int:
                return int == (rhs.value as? Int)
            case let double as Double:
                return double == (rhs.value as? Double)
            case let string as String:
                return string == (rhs.value as? String)
            case let array as [Sendable]:
                guard let rhsArray = rhs.value as? [Sendable] else { return false }
                return array.count == rhsArray.count
                    && zip(array, rhsArray).allSatisfy {
                        AnyCodable($0) == AnyCodable($1)
                    }
            case let dict as [String: Sendable]:
                guard let rhsDict = rhs.value as? [String: Sendable] else { return false }
                guard dict.keys.count == rhsDict.keys.count else { return false }
                return dict.keys.allSatisfy { key in
                    guard let lhsValue = dict[key], let rhsValue = rhsDict[key] else { return false }
                    return AnyCodable(lhsValue) == AnyCodable(rhsValue)
                }
            case is NSNull:
                return rhs.value is NSNull
            default:
                return false
            }
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()

            if let bool = try? container.decode(Bool.self) {
                value = bool
            } else if let int = try? container.decode(Int.self) {
                value = int
            } else if let double = try? container.decode(Double.self) {
                value = double
            } else if let string = try? container.decode(String.self) {
                value = string
            } else if let array = try? container.decode([AnyCodable].self) {
                value = array.map(\.value)
            } else if let dictionary = try? container.decode([String: AnyCodable].self) {
                value = dictionary.mapValues(\.value)
            } else if container.decodeNil() {
                value = NSNull()
            } else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "AnyCodable cannot decode value"
                )
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()

            switch value {
            case let bool as Bool:
                try container.encode(bool)
            case let int as Int:
                try container.encode(int)
            case let double as Double:
                try container.encode(double)
            case let string as String:
                try container.encode(string)
            case let array as [Sendable]:
                try container.encode(array.map { AnyCodable($0) })
            case let dict as [String: Sendable]:
                try container.encode(dict.mapValues { AnyCodable($0) })
            case is NSNull:
                try container.encodeNil()
            default:
                let context = EncodingError.Context(
                    codingPath: container.codingPath,
                    debugDescription: "AnyCodable cannot encode value of type \(type(of: value))"
                )
                throw EncodingError.invalidValue(value, context)
            }
        }
    }
}
