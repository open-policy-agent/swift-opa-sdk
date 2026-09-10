import AST
import Config
import Foundation
import Rego

extension OPA {
    /// A single decision log event.
    ///
    /// This is the Swift equivalent of OPA's `EventV1` (`v1/plugins/logs/plugin.go`).
    /// It captures the state of a single policy decision: what was asked
    /// (`path`/`query`), the `input` provided, the `result` produced, and
    /// bookkeeping metadata (`labels`, bundle revisions, timestamp, and any
    /// masking that was applied).
    ///
    /// Events are built in ``OPA/Runtime/decision(_:input:decisionID:)`` after a
    /// decision is evaluated, run through the drop/mask policies, and then handed
    /// to a ``DecisionLogger`` for buffering and upload.
    ///
    /// ## v1 scope
    ///
    /// The following OPA `EventV1` fields are intentionally omitted for now:
    /// `metrics`, `nd_builtin_cache`, and `request_context`.
    public struct DecisionLogEvent: Codable, Sendable, Equatable {
        /// Deployment labels, sourced from `config.labels` plus SDK-provided
        /// identifiers (`id`, `version`).
        public var labels: [String: String]

        /// The unique identifier for this decision.
        public var decisionID: String

        /// The OPA-style policy path that was queried (e.g. `authz/allow`).
        /// Present when the query is a plain data-document lookup.
        public var path: String?

        /// The raw query string, retained when it isn't a plain data path.
        public var query: String?

        /// The input document provided to the decision.
        public var input: AST.RegoValue?

        /// The (possibly masked) result of the decision.
        public var result: AST.RegoValue?

        /// When the decision was made.
        public var timestamp: Date

        /// Revisions of the bundles that were active at decision time,
        /// keyed by bundle name.
        public var bundles: [String: BundleInfo]?

        /// JSON pointer paths removed by the mask policy (`op: remove`).
        public var erased: [String]?

        /// JSON pointer paths modified by the mask policy (`op: upsert`).
        public var masked: [String]?

        /// The evaluation error, if the decision failed. When set, `result`
        /// is typically absent.
        public var error: String?

        /// Per-bundle revision info.
        public struct BundleInfo: Codable, Sendable, Equatable {
            public var revision: String

            public init(revision: String) {
                self.revision = revision
            }
        }

        public init(
            labels: [String: String] = [:],
            decisionID: String,
            path: String? = nil,
            query: String? = nil,
            input: AST.RegoValue? = nil,
            result: AST.RegoValue? = nil,
            timestamp: Date,
            bundles: [String: BundleInfo]? = nil,
            erased: [String]? = nil,
            masked: [String]? = nil,
            error: String? = nil
        ) {
            self.labels = labels
            self.decisionID = decisionID
            self.path = path
            self.query = query
            self.input = input
            self.result = result
            self.timestamp = timestamp
            self.bundles = bundles
            self.erased = erased
            self.masked = masked
            self.error = error
        }

        enum CodingKeys: String, CodingKey {
            case labels
            case decisionID = "decision_id"
            case path
            case query
            case input
            case result
            case timestamp
            case bundles
            case erased
            case masked
            case error
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            // Labels are always emitted (matches OPA, which always sends labels).
            try container.encode(labels, forKey: .labels)
            try container.encode(decisionID, forKey: .decisionID)
            try container.encodeIfPresent(path, forKey: .path)
            try container.encodeIfPresent(query, forKey: .query)
            try container.encodeIfPresent(input, forKey: .input)
            try container.encodeIfPresent(result, forKey: .result)
            try container.encode(timestamp, forKey: .timestamp)
            try container.encodeIfPresent(bundles, forKey: .bundles)
            try container.encodeIfPresent(erased, forKey: .erased)
            try container.encodeIfPresent(masked, forKey: .masked)
            try container.encodeIfPresent(error, forKey: .error)
        }
    }
}
