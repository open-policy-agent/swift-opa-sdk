import AST
import Rego
import Testing

@testable import Runtime

@Suite("DecisionLogPolicy masking helpers")
struct DecisionLogMaskingTests {
    // MARK: - Path conversion

    @Test("configPathToQuery converts OPA config paths to engine queries")
    func testConfigPathToQuery() {
        #expect(OPA.DecisionLogMaskDropPolicy.configPathToQuery("/system/log/mask") == "data/system/log/mask")
        #expect(OPA.DecisionLogMaskDropPolicy.configPathToQuery("system/log/drop") == "data/system/log/drop")
        #expect(OPA.DecisionLogMaskDropPolicy.configPathToQuery("/") == nil)
        #expect(OPA.DecisionLogMaskDropPolicy.configPathToQuery("") == nil)
    }

    @Test("queryToEventPath strips the data prefix into OPA path form")
    func testQueryToEventPath() {
        #expect(OPA.DecisionLogMaskDropPolicy.queryToEventPath("data/foo/hello") == "foo/hello")
        #expect(OPA.DecisionLogMaskDropPolicy.queryToEventPath("data.foo.hello") == "foo/hello")
        #expect(OPA.DecisionLogMaskDropPolicy.queryToEventPath("data") == nil)
        #expect(OPA.DecisionLogMaskDropPolicy.queryToEventPath("notdata/x") == nil)
    }

    // MARK: - Result-set unwrapping / drop

    @Test("decisionValue unwraps the result wrapper")
    func testDecisionValue() {
        let rs: Rego.ResultSet = [["result": 1]]
        #expect(OPA.DecisionLogMaskDropPolicy.decisionValue(from: rs) == 1)
        #expect(OPA.DecisionLogMaskDropPolicy.decisionValue(from: []) == nil)
    }

    @Test("shouldDrop only fires on boolean true")
    func testShouldDrop() {
        #expect(OPA.DecisionLogMaskDropPolicy.shouldDrop([["result": true]]) == true)
        #expect(OPA.DecisionLogMaskDropPolicy.shouldDrop([["result": false]]) == false)
        #expect(OPA.DecisionLogMaskDropPolicy.shouldDrop([]) == false)
        #expect(OPA.DecisionLogMaskDropPolicy.shouldDrop([["result": "yes"]]) == false)
    }

    // MARK: - Mask rule parsing

    @Test("parseMaskRules accepts bare string pointers as remove rules")
    func testParseBarePointer() {
        let value: AST.RegoValue = ["/input/password"]
        let rules = OPA.DecisionLogMaskDropPolicy.parseMaskRules(from: value)
        #expect(rules == [.init(op: .remove, path: ["input", "password"])])
    }

    @Test("parseMaskRules accepts object rules with op/path/value")
    func testParseObjectRule() {
        let value: AST.RegoValue = [
            ["op": "upsert", "path": "/input/ssn", "value": "***"],
            ["op": "remove", "path": "/result/secret"],
        ]
        let rules = OPA.DecisionLogMaskDropPolicy.parseMaskRules(from: value)
        #expect(rules.count == 2)
        #expect(rules[0] == .init(op: .upsert, path: ["input", "ssn"], value: "***"))
        #expect(rules[1] == .init(op: .remove, path: ["result", "secret"]))
    }

    @Test("parseMaskRules accepts a set of rules and array-form paths")
    func testParseSetAndArrayPath() {
        let value: AST.RegoValue = .set([["op": "remove", "path": ["input", "a"]]])
        let rules = OPA.DecisionLogMaskDropPolicy.parseMaskRules(from: value)
        #expect(rules == [.init(op: .remove, path: ["input", "a"])])
    }

    @Test("parseMaskRules defaults missing op to remove and skips malformed rules")
    func testParseDefaultsAndSkips() {
        let value: AST.RegoValue = [
            ["path": "/input/x"],  // no op -> remove
            ["op": "remove"],  // no path -> skipped
            42,  // not a rule -> skipped
        ]
        let rules = OPA.DecisionLogMaskDropPolicy.parseMaskRules(from: value)
        #expect(rules == [.init(op: .remove, path: ["input", "x"])])
    }

    // MARK: - Malformed-rule reporting (drives fail-closed masking)

    @Test("parseMaskRulesReporting reports no malformed rules for well-formed input")
    func testReportingClean() {
        let value: AST.RegoValue = [
            ["op": "upsert", "path": "/input/ssn", "value": "***"],
            "/result/secret",
        ]
        let parsed = OPA.DecisionLogMaskDropPolicy.parseMaskRulesReporting(from: value)
        #expect(parsed.malformed == 0)
        #expect(parsed.rules.count == 2)
    }

    @Test("parseMaskRulesReporting counts each malformed rule but keeps the valid ones")
    func testReportingCountsMalformed() {
        let value: AST.RegoValue = [
            ["path": "/input/x"],  // valid (defaults to remove)
            ["op": "remove"],  // malformed: no path
            42,  // malformed: not a rule
            "",  // malformed: empty pointer
        ]
        let parsed = OPA.DecisionLogMaskDropPolicy.parseMaskRulesReporting(from: value)
        #expect(parsed.rules == [.init(op: .remove, path: ["input", "x"])])
        #expect(parsed.malformed == 3)
    }

    @Test("parseMaskRulesReporting treats a defined non-collection value as malformed")
    func testReportingNonCollection() {
        // A mask policy that returns a scalar (not a set/array of rules) can't be
        // applied — fail-closed callers must drop the event.
        let parsed = OPA.DecisionLogMaskDropPolicy.parseMaskRulesReporting(from: .boolean(true))
        #expect(parsed.rules.isEmpty)
        #expect(parsed.malformed == 1)
    }

    @Test("parseMaskRulesReporting reports nothing for an undefined (nil) decision")
    func testReportingNilIsClean() {
        // An undefined mask decision is the no-policy case, not an error.
        let parsed = OPA.DecisionLogMaskDropPolicy.parseMaskRulesReporting(from: nil)
        #expect(parsed.rules.isEmpty)
        #expect(parsed.malformed == 0)
    }

    // MARK: - Applying rules

    @Test("apply removes and upserts within input/result, tracking erased/masked")
    func testApply() {
        var event = OPA.DecisionLogEvent(
            decisionID: "d1",
            input: ["password": "hunter2", "user": "alice"],
            result: ["allowed": true, "secret": "xyz"],
            timestamp: .init(timeIntervalSince1970: 0))

        let rules: [OPA.DecisionLogMaskDropPolicy.MaskRule] = [
            .init(op: .remove, path: ["input", "password"]),
            .init(op: .upsert, path: ["result", "secret"], value: "***"),
        ]
        OPA.DecisionLogMaskDropPolicy.apply(rules: rules, to: &event)

        #expect(event.input == ["user": "alice"])
        #expect(event.result == ["allowed": true, "secret": "***"])
        #expect(event.erased == ["/input/password"])
        #expect(event.masked == ["/result/secret"])
    }

    @Test("apply ignores rules targeting unknown roots")
    func testApplyUnknownRoot() {
        var event = OPA.DecisionLogEvent(
            decisionID: "d1",
            input: ["a": 1],
            timestamp: .init(timeIntervalSince1970: 0))
        OPA.DecisionLogMaskDropPolicy.apply(
            rules: [.init(op: .remove, path: ["nonexistent", "x"])], to: &event)
        #expect(event.input == ["a": 1])
        #expect(event.erased == nil)
    }

    @Test("remove of an absent nested path is not recorded in erased")
    func testRemoveAbsentNotRecorded() {
        var event = OPA.DecisionLogEvent(
            decisionID: "d1",
            input: ["user": "alice"],
            timestamp: .init(timeIntervalSince1970: 0))
        // The `input` field exists but has no `missing` key, so nothing changes
        // and the pointer must not appear in `erased` (misleading audit trail).
        OPA.DecisionLogMaskDropPolicy.apply(
            rules: [.init(op: .remove, path: ["input", "missing"])], to: &event)
        #expect(event.input == ["user": "alice"])
        #expect(event.erased == nil)
    }

    @Test("upsert overwrites an existing scalar leaf, nested and shallow")
    func testUpsertOverwritesExistingLeaf() {
        var event = OPA.DecisionLogEvent(
            decisionID: "d1",
            input: ["password": "hunter2"],
            result: ["user": ["ssn": "123-45-6789", "name": "alice"]],
            timestamp: .init(timeIntervalSince1970: 0))

        OPA.DecisionLogMaskDropPolicy.apply(
            rules: [
                .init(op: .upsert, path: ["input", "password"], value: "***"),
                .init(op: .upsert, path: ["result", "user", "ssn"], value: "***"),
            ], to: &event)

        #expect(event.input == ["password": "***"])
        // The sibling `name` survives. only the addressed leaf is overwritten.
        #expect(event.result == ["user": ["ssn": "***", "name": "alice"]])
        #expect(Set(event.masked ?? []) == ["/input/password", "/result/user/ssn"])
    }

    @Test("upsert replaces an existing object value wholesale, not a deep merge")
    func testUpsertReplacesObjectWholesale() {
        var event = OPA.DecisionLogEvent(
            decisionID: "d1",
            result: ["user": ["ssn": "123", "name": "alice"]],
            timestamp: .init(timeIntervalSince1970: 0))
        // Overwriting /result/user with a new object must drop the old keys
        // (`name`), matching OPA's "if the field exists it is overwritten".
        OPA.DecisionLogMaskDropPolicy.apply(
            rules: [.init(op: .upsert, path: ["result", "user"], value: ["ssn": "***"])],
            to: &event)
        #expect(event.result == ["user": ["ssn": "***"]])
    }

    @Test("upsert adds a missing key when the parent is an object")
    func testUpsertAddsMissingKey() {
        var event = OPA.DecisionLogEvent(
            decisionID: "d1",
            result: ["allowed": true],
            timestamp: .init(timeIntervalSince1970: 0))
        OPA.DecisionLogMaskDropPolicy.apply(
            rules: [.init(op: .upsert, path: ["result", "reason"], value: "ok")], to: &event)
        #expect(event.result == ["allowed": true, "reason": "ok"])
        #expect(event.masked == ["/result/reason"])
    }

    @Test("upsert of the whole field overwrites even a scalar value")
    func testUpsertWholeFieldOverwritesScalar() {
        var event = OPA.DecisionLogEvent(
            decisionID: "d1",
            result: 1,
            timestamp: .init(timeIntervalSince1970: 0))
        // rest is empty, so the entire `result` is replaced regardless of type.
        OPA.DecisionLogMaskDropPolicy.apply(
            rules: [.init(op: .upsert, path: ["result"], value: "***")], to: &event)
        #expect(event.result == "***")
        #expect(event.masked == ["/result"])
    }

    @Test("upsert into a scalar field is refused, leaving the value intact")
    func testUpsertIntoScalarRefused() {
        var event = OPA.DecisionLogEvent(
            decisionID: "d1",
            result: 1,
            timestamp: .init(timeIntervalSince1970: 0))
        // Upserting a nested path into a scalar `result` would clobber the `1`
        // with `{"x": "***"}`. The rule is refused, keeping the real result.
        OPA.DecisionLogMaskDropPolicy.apply(
            rules: [.init(op: .upsert, path: ["result", "x"], value: "***")], to: &event)
        #expect(event.result == 1)
        #expect(event.masked == nil)
    }

    @Test("upsert blocks on a present scalar intermediate, leaving it intact")
    func testUpsertBlocksOnScalarIntermediate() {
        var event = OPA.DecisionLogEvent(
            decisionID: "d1",
            input: ["a": 1, "keep": "me"],
            timestamp: .init(timeIntervalSince1970: 0))
        // `a` is a present scalar intermediate for path /input/a/b. Per OPA the
        // whole operation is blocked: `a` must not be paved over into an object,
        // and no part of the event changes.
        OPA.DecisionLogMaskDropPolicy.apply(
            rules: [.init(op: .upsert, path: ["input", "a", "b"], value: "***")], to: &event)
        #expect(event.input == ["a": 1, "keep": "me"])
        #expect(event.masked == nil)
    }

    @Test("upsert creates missing object intermediates down to the final key")
    func testUpsertCreatesMissingIntermediates() {
        var event = OPA.DecisionLogEvent(
            decisionID: "d1",
            input: ["existing": true],
            timestamp: .init(timeIntervalSince1970: 0))
        OPA.DecisionLogMaskDropPolicy.apply(
            rules: [.init(op: .upsert, path: ["input", "a", "b", "c"], value: "***")], to: &event)
        #expect(event.input == ["existing": true, "a": ["b": ["c": "***"]]])
        #expect(event.masked == ["/input/a/b/c"])
    }
}

@Suite("RegoValue.removing(at:)")
struct RegoValueRemoveTests {
    @Test("removes a nested key")
    func testRemoveNested() {
        let v: AST.RegoValue = ["a": ["b": 1, "c": 2]]
        #expect(v.removing(at: ["a", "b"]) == ["a": ["c": 2]])
    }

    @Test("removing an absent path is a no-op")
    func testRemoveAbsent() {
        let v: AST.RegoValue = ["a": ["b": 1]]
        #expect(v.removing(at: ["a", "z"]) == v)
        #expect(v.removing(at: ["x", "y"]) == v)
    }

    @Test("removing the empty path resets to an empty object")
    func testRemoveEmpty() {
        let v: AST.RegoValue = ["a": 1]
        #expect(v.removing(at: []) == .object([:]))
    }

    @Test("descending into a scalar is a no-op")
    func testRemoveIntoScalar() {
        let v: AST.RegoValue = ["a": 1]
        #expect(v.removing(at: ["a", "b"]) == v)
    }

    @Test("removes an array element by index, compacting the array")
    func testRemoveArrayElement() {
        let v: AST.RegoValue = ["items": ["x", "y", "z"]]
        #expect(v.removing(at: ["items", "1"]) == ["items": ["x", "z"]])
    }

    @Test("out-of-bounds or non-integer array index is a no-op")
    func testRemoveArrayBadIndex() {
        let v: AST.RegoValue = ["items": ["x", "y"]]
        #expect(v.removing(at: ["items", "5"]) == v)
        #expect(v.removing(at: ["items", "notint"]) == v)
    }
}
