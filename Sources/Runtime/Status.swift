import Foundation
import Rego

// The per-bundle status model. Field names and JSON keys mirror OPA's Status
// API `"bundles"` section (https://www.openpolicyagent.org/docs/management-status),
// minus the per-bundle `metrics` object (handled globally, later).

extension OPA {
    /// A single human-readable bundle error, string-backed so the enclosing
    /// metadata stays `Sendable`/`Equatable`/`Codable`.
    public struct StatusError: Error, Codable, Equatable, Sendable, CustomStringConvertible {
        public let message: String
        public var description: String { message }
        public init(message: String) { self.message = message }
    }

    /// A bundle's fetch and activation status, modeled on OPA's Status API
    /// `"bundles"` entries.
    public struct BundleStatusMetadata: Sendable, Equatable {
        /// The bundle name (its key in the config `bundles` section).
        public var name: String
        /// Opaque identifier of the last successful activation (bundle manifest
        /// revision). Empty when nothing has been activated.
        public var activeRevision: String
        /// ETag of the last-known-good bundle. Retained across failing polls.
        public var etag: String?
        /// Size in bytes of the last downloaded bundle body (compressed for
        /// HTTP sources, `nil` for directory sources or when unknown).
        public var size: Int?
        /// Bundle type — `"snapshot"` today (delta bundles are unsupported).
        public var type: String?
        /// Timestamp of the last poll attempt (advances on failures too).
        public var lastRequest: Date?
        /// Timestamp of the last successful request (advances on HTTP 304 too).
        public var lastSuccessfulRequest: Date?
        /// Timestamp of the last successful fresh download.
        public var lastSuccessfulDownload: Date?
        /// Timestamp of the last successful activation (a new bundle took effect).
        public var lastSuccessfulActivation: Date?
        /// Error code, present only when the most recent poll failed.
        public var code: String?
        /// Human-readable error message, present only on failure.
        public var message: String?
        /// HTTP status code, when a failure carried one.
        public var httpCode: Int?
        /// Detailed errors, present only on failure.
        public var errors: [OPA.StatusError]?

        public init(
            name: String,
            activeRevision: String = "",
            etag: String? = nil,
            size: Int? = nil,
            type: String? = nil,
            lastRequest: Date? = nil,
            lastSuccessfulRequest: Date? = nil,
            lastSuccessfulDownload: Date? = nil,
            lastSuccessfulActivation: Date? = nil,
            code: String? = nil,
            message: String? = nil,
            httpCode: Int? = nil,
            errors: [OPA.StatusError]? = nil
        ) {
            self.name = name
            self.activeRevision = activeRevision
            self.etag = etag
            self.size = size
            self.type = type
            self.lastRequest = lastRequest
            self.lastSuccessfulRequest = lastSuccessfulRequest
            self.lastSuccessfulDownload = lastSuccessfulDownload
            self.lastSuccessfulActivation = lastSuccessfulActivation
            self.code = code
            self.message = message
            self.httpCode = httpCode
            self.errors = errors
        }
    }

    /// A bundle's status paired with the currently-enforced bundle payload.
    ///
    /// `bundle == nil` distinguishes "never activated" (possibly with a recorded
    /// error) from "activated, and the most recent refresh may have failed"
    /// (`bundle != nil` alongside a non-nil `metadata.code`).
    public struct BundleStatus: Sendable, Equatable {
        public let metadata: OPA.BundleStatusMetadata
        public let bundle: OPA.Bundle?
        public init(metadata: OPA.BundleStatusMetadata, bundle: OPA.Bundle?) {
            self.metadata = metadata
            self.bundle = bundle
        }
    }
}

// MARK: - Codable (OPA Status API JSON shape)

extension OPA.BundleStatusMetadata: Codable {
    private enum CodingKeys: String, CodingKey {
        case name
        case activeRevision = "active_revision"
        case etag
        case size
        case type
        case lastRequest = "last_request"
        case lastSuccessfulRequest = "last_successful_request"
        case lastSuccessfulDownload = "last_successful_download"
        case lastSuccessfulActivation = "last_successful_activation"
        case code
        case message
        case httpCode = "http_code"
        case errors
    }

    /// RFC3339 with fractional seconds, matching OPA's Status API output.
    /// Encoded/decoded explicitly so the wire format does not depend on the
    /// caller's `JSONEncoder.dateEncodingStrategy`. `ISO8601DateFormatter` is
    /// not `Sendable` and not safe for concurrent use, so each coding pass makes
    /// its own. Status (de)serialization is infrequent.
    private static func makeISO8601(fractionalSeconds: Bool = true) -> ISO8601DateFormatter {
        let f = ISO8601DateFormatter()
        f.formatOptions =
            fractionalSeconds ? [.withInternetDateTime, .withFractionalSeconds] : [.withInternetDateTime]
        return f
    }

    public func encode(to encoder: any Encoder) throws {
        let iso = Self.makeISO8601()
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(name, forKey: .name)
        try c.encodeIfPresent(activeRevision.isEmpty ? nil : activeRevision, forKey: .activeRevision)
        try c.encodeIfPresent(etag, forKey: .etag)
        try c.encodeIfPresent(size, forKey: .size)
        try c.encodeIfPresent(type, forKey: .type)
        try c.encodeIfPresent(lastRequest.map(iso.string(from:)), forKey: .lastRequest)
        try c.encodeIfPresent(
            lastSuccessfulRequest.map(iso.string(from:)), forKey: .lastSuccessfulRequest)
        try c.encodeIfPresent(
            lastSuccessfulDownload.map(iso.string(from:)), forKey: .lastSuccessfulDownload)
        try c.encodeIfPresent(
            lastSuccessfulActivation.map(iso.string(from:)), forKey: .lastSuccessfulActivation)
        try c.encodeIfPresent(code, forKey: .code)
        try c.encodeIfPresent(message, forKey: .message)
        try c.encodeIfPresent(httpCode, forKey: .httpCode)
        if let errors, !errors.isEmpty {
            try c.encode(errors.map(\.message), forKey: .errors)
        }
    }

    public init(from decoder: any Decoder) throws {
        let iso = Self.makeISO8601()
        let isoPlain = Self.makeISO8601(fractionalSeconds: false)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        activeRevision = try c.decodeIfPresent(String.self, forKey: .activeRevision) ?? ""
        etag = try c.decodeIfPresent(String.self, forKey: .etag)
        size = try c.decodeIfPresent(Int.self, forKey: .size)
        type = try c.decodeIfPresent(String.self, forKey: .type)
        func date(_ key: CodingKeys) throws -> Date? {
            guard let s = try c.decodeIfPresent(String.self, forKey: key) else { return nil }
            // Accept RFC3339 with or without fractional seconds.
            return iso.date(from: s) ?? isoPlain.date(from: s)
        }
        lastRequest = try date(.lastRequest)
        lastSuccessfulRequest = try date(.lastSuccessfulRequest)
        lastSuccessfulDownload = try date(.lastSuccessfulDownload)
        lastSuccessfulActivation = try date(.lastSuccessfulActivation)
        code = try c.decodeIfPresent(String.self, forKey: .code)
        message = try c.decodeIfPresent(String.self, forKey: .message)
        httpCode = try c.decodeIfPresent(Int.self, forKey: .httpCode)
        if let messages = try c.decodeIfPresent([String].self, forKey: .errors) {
            errors = messages.map { OPA.StatusError(message: $0) }
        } else {
            errors = nil
        }
    }
}
