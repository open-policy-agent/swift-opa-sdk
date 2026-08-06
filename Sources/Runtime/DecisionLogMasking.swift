import AST
import Foundation
import Rego

extension OPA {
    /// Pure helpers for decision-log drop/mask policy handling.
    ///
    /// The orchestration (preparing + evaluating the policies against loaded
    /// bundles) lives in ``OPA/Runtime``. This enum holds the stateless pieces
    /// so they can be unit-tested in isolation:
    ///  - Path conversion between OPA config decision paths, engine query
    ///    strings, and OPA-style event paths.
    ///  - Parsing the mask policy's result into ``MaskRule`` values.
    ///  - Applying those rules to a ``DecisionLogEvent``.
    ///  - Interpreting a drop policy result set as a boolean.
    ///
    /// Mask/drop policies come from the normal loaded bundles (they must be
    /// compiled as entrypoints, e.g. `system/log/mask`). The mask policy
    /// receives the decision log event as its `input` document and returns a
    /// set/array of rules.
    /// See:
    /// https://www.openpolicyagent.org/docs/management-decision-logs#masking-sensitive-data
    public enum DecisionLogMaskDropPolicy {
        // MARK: - Path conversion

        /// Converts an OPA config decision path such as `/system/log/mask`
        /// into the engine query form `data/system/log/mask`.
        ///
        /// Leading/trailing slashes are trimmed and a `data` prefix is added.
        /// An empty or `/`-only path yields `nil` (no policy configured).
        public static func configPathToQuery(_ path: String) -> String? {
            let segments = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
            guard !segments.isEmpty else { return nil }
            return (["data"] + segments).joined(separator: "/")
        }

        /// Converts an engine query string (`data/foo/bar` or `data.foo.bar`)
        /// into the OPA event path form `foo/bar`. Returns `nil` for the bare
        /// `data` root or a malformed query.
        public static func queryToEventPath(_ query: String) -> String? {
            let prefix = "data"
            guard query.hasPrefix(prefix) else { return nil }
            if query == prefix { return nil }
            let tail = query.dropFirst(prefix.count + 1)
            guard !tail.isEmpty else { return nil }
            return tail.replacingOccurrences(of: ".", with: "/")
        }

        // MARK: - Result-set unwrapping

        /// Extracts the single decision value from a result set produced by
        /// evaluating an entrypoint query. The SDK wraps entrypoint output as
        /// `{"result": <value>}`, so this returns that inner value. Returns
        /// `nil` when the result set is empty (undefined decision).
        public static func decisionValue(from resultSet: Rego.ResultSet) -> AST.RegoValue? {
            guard let first = resultSet.first else { return nil }
            if case .object(let o) = first, let v = o[.string("result")] {
                return v
            }
            return first
        }

        /// Interprets a drop policy's result set. The event is dropped only
        /// when the decision value is boolean `true`.
        public static func shouldDrop(_ resultSet: Rego.ResultSet) -> Bool {
            if case .boolean(true) = decisionValue(from: resultSet) {
                return true
            }
            return false
        }

        // MARK: - Mask rules

        /// A single mask operation, as emitted by a `system/log/mask` policy.
        public struct MaskRule: Equatable, Sendable {
            public enum Op: String, Sendable {
                case remove
                case upsert
            }

            /// The operation to perform (`remove` by default).
            public var op: Op
            /// Parsed path segments (JSON-pointer form), e.g. `["input", "password"]`.
            public var path: [String]
            /// Replacement value for `upsert`.
            public var value: AST.RegoValue?

            public init(op: Op, path: [String], value: AST.RegoValue? = nil) {
                self.op = op
                self.path = path
                self.value = value
            }
        }

        /// Result of parsing a mask policy's decision value: the rules we could
        /// parse, plus a count of rule elements that were malformed (present in
        /// the policy output but not parseable into a ``MaskRule``).
        ///
        /// A caller enforcing fail-closed masking must treat `malformed > 0` as
        /// an error and drop the event, since a rule the policy emitted to
        /// redact a field could not be applied.
        public struct MaskRuleParse: Equatable, Sendable {
            public var rules: [MaskRule]
            public var malformed: Int

            public init(rules: [MaskRule], malformed: Int) {
                self.rules = rules
                self.malformed = malformed
            }
        }

        /// Parses the mask policy's decision value into a list of rules.
        ///
        /// Accepts either a set or an array of rules. Each rule is either a
        /// bare string/array JSON pointer (implying `remove`) or an object
        /// `{"op": "remove"|"upsert", "path": <pointer>, "value": <any>}`.
        /// Malformed rules are skipped. Use ``parseMaskRulesReporting(from:)``
        /// when a malformed rule must fail the whole event closed.
        public static func parseMaskRules(from value: AST.RegoValue?) -> [MaskRule] {
            parseMaskRulesReporting(from: value).rules
        }

        /// Parses the mask policy's decision value, also reporting how many rule
        /// elements were malformed (see ``MaskRuleParse``). A `nil` value (an
        /// undefined mask decision) yields no rules and no malformed count. A
        /// defined value that isn't a set/array of rules is itself malformed.
        public static func parseMaskRulesReporting(from value: AST.RegoValue?) -> MaskRuleParse {
            guard let value else { return MaskRuleParse(rules: [], malformed: 0) }
            let elements: [AST.RegoValue]
            switch value {
            case .array(let a): elements = a
            case .set(let s): elements = Array(s)
            default:
                // A defined mask decision that isn't a collection of rules.
                return MaskRuleParse(rules: [], malformed: 1)
            }

            var rules: [MaskRule] = []
            var malformed = 0
            for element in elements {
                switch element {
                case .string, .array:
                    // Bare pointer -> remove.
                    if let path = parsePointer(element) {
                        rules.append(MaskRule(op: .remove, path: path))
                    } else {
                        malformed += 1
                    }
                case .object(let o):
                    guard let pointer = o[.string("path")], let path = parsePointer(pointer) else {
                        malformed += 1
                        continue
                    }
                    let op: MaskRule.Op
                    if case .string(let s) = o[.string("op")], let parsed = MaskRule.Op(rawValue: s) {
                        op = parsed
                    } else {
                        op = .remove
                    }
                    rules.append(MaskRule(op: op, path: path, value: o[.string("value")]))
                default:
                    malformed += 1
                }
            }
            return MaskRuleParse(rules: rules, malformed: malformed)
        }

        /// Parses a JSON pointer expressed as either a `/`-delimited string
        /// (`/input/password`) or an array of segments (`["input", "password"]`).
        /// Returns `nil` if empty or malformed.
        static func parsePointer(_ value: AST.RegoValue) -> [String]? {
            switch value {
            case .string(let s):
                let segments = s.split(separator: "/", omittingEmptySubsequences: true).map {
                    unescapePointerSegment(String($0))
                }
                return segments.isEmpty ? nil : segments
            case .array(let a):
                var out: [String] = []
                for elem in a {
                    guard case .string(let s) = elem else { return nil }
                    out.append(s)
                }
                return out.isEmpty ? nil : out
            default:
                return nil
            }
        }

        /// Unescapes JSON pointer reference tokens (`~1` -> `/`, `~0` -> `~`).
        private static func unescapePointerSegment(_ segment: String) -> String {
            segment.replacingOccurrences(of: "~1", with: "/")
                .replacingOccurrences(of: "~0", with: "~")
        }

        // MARK: - Applying rules

        /// Applies the given mask rules to `event`, populating its `erased`
        /// and `masked` pointer lists. Rules target the event's top-level
        /// fields (`input`, `result`). Rules pointing elsewhere are ignored.
        public static func apply(rules: [MaskRule], to event: inout DecisionLogEvent) {
            guard !rules.isEmpty else { return }
            var erased: [String] = []
            var masked: [String] = []

            for rule in rules {
                guard let root = rule.path.first else { continue }
                let rest = Array(rule.path.dropFirst())
                let pointer = "/" + rule.path.joined(separator: "/")

                switch rule.op {
                case .remove:
                    if applyRemove(root: root, rest: rest, event: &event) {
                        erased.append(pointer)
                    }
                case .upsert:
                    guard let value = rule.value else { continue }
                    if applyUpsert(root: root, rest: rest, value: value, event: &event) {
                        masked.append(pointer)
                    }
                }
            }

            if !erased.isEmpty {
                event.erased = (event.erased ?? []) + erased
            }
            if !masked.isEmpty {
                event.masked = (event.masked ?? []) + masked
            }
        }

        /// Removes the value at `rest` under the named top-level field.
        /// Returns `true` only when the field actually changed, so a rule that
        /// targets an absent nested path doesn't get recorded in `erased`.
        private static func applyRemove(root: String, rest: [String], event: inout DecisionLogEvent) -> Bool {
            switch root {
            case "input":
                guard let input = event.input else { return false }
                if rest.isEmpty {
                    event.input = nil
                    return true
                }
                let updated = input.removing(at: rest)
                guard updated != input else { return false }
                event.input = updated
                return true
            case "result":
                guard let result = event.result else { return false }
                if rest.isEmpty {
                    event.result = nil
                    return true
                }
                let updated = result.removing(at: rest)
                guard updated != result else { return false }
                event.result = updated
                return true
            default:
                return false
            }
        }

        /// Upserts `value` at `rest` under the named top-level field, or leaves
        /// the field untouched when the upsert is blocked.
        private static func applyUpsert(
            root: String, rest: [String], value: AST.RegoValue, event: inout DecisionLogEvent
        ) -> Bool {
            switch root {
            case "input":
                guard let updated = upserted(base: event.input, rest: rest, value: value) else {
                    return false
                }
                event.input = updated
                return true
            case "result":
                guard let updated = upserted(base: event.result, rest: rest, value: value) else {
                    return false
                }
                event.result = updated
                return true
            default:
                return false
            }
        }

        /// Computes the upserted value for a top-level field, mirroring OPA's
        /// upsert semantics, or nil when the whole operation is blocked:
        ///  - Missing intermediate keys are created as objects.
        ///  - A present non-object intermediate blocks the whole operation
        ///    (nothing is written), rather than clobbering that value.
        ///  - Only the final segment overwrites an existing value, scalar or
        ///    object (an object is replaced wholesale, not merged).
        ///
        /// `rest` is the path below the top-level field. An empty `rest` replaces
        /// the entire field. The field's own value acts as the first container,
        /// so a scalar there blocks a nested upsert just like any other
        /// intermediate.
        private static func upserted(
            base: AST.RegoValue?, rest: [String], value: AST.RegoValue
        ) -> AST.RegoValue? {
            // Replacing the whole field always applies.
            guard !rest.isEmpty else { return value }
            // An absent field becomes a fresh object. A present scalar/array
            // can't hold the next segment, so the operation is blocked.
            let container = base ?? .object([:])
            guard case .object = container else { return nil }
            return upsert(into: container, rest: rest[...], value: value)
        }

        /// Recursive core of ``upserted``. `node` is guaranteed to be an object.
        /// Descends `rest`, creating missing object intermediates and blocking
        /// (returning nil) on a present non-object intermediate.
        private static func upsert(
            into node: AST.RegoValue, rest: ArraySlice<String>, value: AST.RegoValue
        ) -> AST.RegoValue? {
            guard case .object(var o) = node, let segment = rest.first else { return nil }
            let key = AST.RegoValue.string(segment)
            let tail = rest.dropFirst()

            // Final segment: overwrite (or add) the value unconditionally.
            if tail.isEmpty {
                o[key] = value
                return .object(o)
            }

            // Intermediate segment: descend into an object, create a missing
            // key, or block on a present non-object.
            let child: AST.RegoValue
            if let existing = o[key] {
                guard case .object = existing else { return nil }
                child = existing
            } else {
                child = .object([:])
            }
            guard let updated = upsert(into: child, rest: tail, value: value) else {
                return nil
            }
            o[key] = updated
            return .object(o)
        }
    }
}
