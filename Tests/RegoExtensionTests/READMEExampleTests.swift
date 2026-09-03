import AST
import Foundation
import Rego
import Testing

// Exercises the OPA.Engine + yaml.* integration: create an engine, prepare a
// query, and evaluate a policy that calls a yaml.* built-in. Since swift-opa
// >= 0.0.10 provides yaml.* natively, no custom builtins need to be registered.
@Suite("READMEExampleTests")
struct READMEExampleTests {
    @Test func testREADMEExample() async throws {
        // Bundle containing a single plan: test/allow := yaml.is_valid(input.yaml_str)
        // Static strings[0] = "result" (output key), strings[1] = "yaml_str" (input field).
        let planData = """
            {
            "static":{"strings":[{"value":"result"},{"value":"yaml_str"}],"files":[{"value":"test.rego"}]},
            "plans":{"plans":[{"name":"test/allow","blocks":[{"stmts":[
            {"type":"AssignVarOnceStmt","stmt":{"source":{"type":"local","value":0},"target":5,"file":0,"col":0,"row":0}},
            {"type":"DotStmt","stmt":{"source":{"type":"local","value":5},"key":{"type":"string_index","value":1},"target":6,"file":0,"col":0,"row":0}},
            {"type":"CallStmt","stmt":{"func":"yaml.is_valid","args":[{"type":"local","value":6}],"result":2,"file":0,"col":0,"row":0}},
            {"type":"AssignVarStmt","stmt":{"source":{"type":"local","value":2},"target":3,"file":0,"col":0,"row":0}},
            {"type":"MakeObjectStmt","stmt":{"target":4,"file":0,"col":0,"row":0}},
            {"type":"ObjectInsertStmt","stmt":{"key":{"type":"string_index","value":0},"value":{"type":"local","value":3},"object":4,"file":0,"col":0,"row":0}},
            {"type":"ResultSetAddStmt","stmt":{"value":4,"file":0,"col":0,"row":0}}
            ]}]}]},
            "funcs":{"funcs":[]}
            }
            """.data(using: .utf8)!

        let manifest = OPA.Manifest(revision: "1", roots: ["test"])
        let bundle = try OPA.Bundle(
            manifest: manifest,
            planFiles: [Rego.BundleFile(url: URL(string: "/plan.json")!, data: planData)],
            regoFiles: [],
            data: .object([:])
        )

        var engine = OPA.Engine(
            bundles: ["test": bundle],
            capabilities: nil
        )

        let pq = try await engine.prepareForEvaluation(query: "data/test/allow")
        let result = try await pq.evaluate(input: .object(["yaml_str": .string("valid: true")]))
        #expect(result.first == ["result": .boolean(true)])
    }
}
