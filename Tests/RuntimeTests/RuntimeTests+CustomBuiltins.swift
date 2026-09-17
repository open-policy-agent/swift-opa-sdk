import AST
import Foundation
import Rego
import Testing

@testable import Runtime

// MARK: - Custom Builtins Tests

@Suite("RuntimeCustomBuiltinsTests")
struct RuntimeCustomBuiltinsTests {
    let customBuiltinRegistry: [String: Rego.BuiltinImpl] =
        [
            // a + (b * c) = output
            "custom_fma": .sync({ ctx, args in
                guard args.count == 3 else {
                    throw BuiltinError.argumentCountMismatch(got: args.count, want: 2)
                }

                guard case .number(let a) = args[0] else {
                    throw BuiltinError.argumentTypeMismatch(arg: "a", got: args[0].typeName, want: "number")
                }

                guard case .number(let b) = args[1] else {
                    throw BuiltinError.argumentTypeMismatch(arg: "b", got: args[1].typeName, want: "number")
                }

                guard case .number(let c) = args[2] else {
                    throw BuiltinError.argumentTypeMismatch(arg: "c", got: args[2].typeName, want: "number")
                }

                return .number(RegoNumber(a.decimalValue + (b.decimalValue * c.decimalValue)))
            })
        ]

    @Test func customBuiltinWorksInRuntime() async throws {
        let baseConfig = #"""
            {
                "bundles" : {
                    "test": {"resource": "file:///{TEMP}/bundle-dir"}
                }
            }
            """#

        let tempDir = try makeTempDir()
        defer {
            try? FileManager.default.removeItem(at: tempDir)
        }
        let testBundle = try makeCustomBuiltinBundle()
        // We have to create the intermediate parent directories for the tarball case,
        // or we'll get an exciting NSError about the file not existing.
        let bundleURL = tempDir.appendingPathComponent("bundle-dir")
        try FileManager.default.createDirectory(
            at: bundleURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try OPA.Bundle.encodeToTarball(bundle: testBundle).write(to: bundleURL)

        // Build an updated OPA Config, then start up the runtime.
        let updatedConfig: Data = baseConfig.replacingOccurrences(of: "{TEMP}", with: tempDir.path()).data(
            using: .utf8)!
        let config: OPA.Config = try JSONDecoder().decode(OPA.Config.self, from: updatedConfig)
        let rt = try OPA.Runtime(config: config, customBuiltins: customBuiltinRegistry)

        let backgroundFetchTask = Task { try await rt.run() }
        defer { backgroundFetchTask.cancel() }
        let _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(1))

        let bundleStorage = rt.activeBundles()
        #expect(bundleStorage.count == 1, "Expected exactly 1 succesful bundle load, got \(bundleStorage.count)")
        #expect(bundleStorage.allSatisfy { $0.value.bundle != nil })

        // Check decision result.
        let dr = try await rt.decision("data/test/custom_builtin", input: .object(["a": 7, "b": 2, "c": 5]))
        #expect(dr.result.first == ["result": 17])
    }

    private func makeCustomBuiltinBundle() throws -> OPA.Bundle {
        let roots = [""]
        let manifest = OPA.Manifest(revision: UUID().uuidString, roots: roots)

        func generateStmtsFMA() -> ([String], [String]) {
            var staticStrings: [String] = [#"{"value": "result"}"#]
            var stmts: [String] = []
            let sourceLocalIdx = 5
            var keyStrIdx = 1
            var targetLocalIdx = 6
            // input -> L5
            stmts.append(
                #"{"type":"AssignVarOnceStmt","stmt":{"source":{"type":"local","value":0},"target":5,"file":0,"col":0,"row":0}}"#
            )
            // input.a -> L6, input.b -> L7, input.c -> L8
            for segment in ["a", "b", "c"] {
                staticStrings.append(#"{"value": "\#(segment)"}"#)
                let dotStmt =
                    #"{"type": "DotStmt", "stmt": {"source": {"type":"local","value":\#(sourceLocalIdx)}, "key": {"type":"string_index","value":\#(keyStrIdx)}, "target": \#(targetLocalIdx), "file":0,"col":0,"row":0}}"#
                keyStrIdx += 1
                targetLocalIdx += 1
                stmts.append(dotStmt)
            }
            // call "custom_fma" [L6, L7, L8] -> L2
            stmts.append(
                #"{"type":"CallStmt","stmt":{"func":"custom_fma","args":[{"type":"local","value":6},{"type":"local","value":7},{"type":"local","value":8}],"result":2,"file":0,"col":0,"row":0}}"#
            )
            return (staticStrings, stmts)
        }

        let (staticStrings, stmts) = generateStmtsFMA()
        return try makeExampleBundle(
            manifest: manifest,
            planFiles: [
                Rego.BundleFile(
                    url: URL(string: "/plan.json")!,
                    data: """
                        {
                        "static":{"strings":[\(staticStrings.joined(separator: ","))],"files":[{"value":"custom_builtin.rego"}]},
                        "plans":{"plans":[{"name":"test/custom_builtin","blocks":[{"stmts":[\(stmts.joined(separator: ",")),
                        {"type":"AssignVarStmt","stmt":{"source":{"type":"local","value":2},"target":3,"file":0,"col":0,"row":0}},
                        {"type":"MakeObjectStmt","stmt":{"target":4,"file":0,"col":0,"row":0}},
                        {"type":"ObjectInsertStmt","stmt":{"key":{"type":"string_index","value":0},"value":{"type":"local","value":3},"object":4,"file":0,"col":0,"row":0}},
                        {"type":"ResultSetAddStmt","stmt":{"value":4,"file":0,"col":0,"row":0}}]}]}]},
                        "funcs":{"funcs":[]}
                        }
                        """.data(using: .utf8)!
                )
            ],
            regoFiles: [],
            data: .object([:])
        )
    }
}
