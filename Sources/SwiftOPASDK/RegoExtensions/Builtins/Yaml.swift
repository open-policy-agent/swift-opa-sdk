import AST
import Foundation
import Rego
import Yams

extension SDKBuiltinFuncs {
    /// Verifies the input string is a valid YAML document.
    public static func yamlIsValid(ctx: BuiltinContext, args: [AST.RegoValue]) async throws -> AST.RegoValue {
        guard args.count == 1 else {
            throw Rego.BuiltinError.argumentCountMismatch(got: args.count, want: 1)
        }

        guard case .string(let rawYAML) = args[0] else {
            throw BuiltinError.argumentTypeMismatch(arg: "x", got: args[0].typeName, want: "string")
        }

        // The result of the YAML parsing should be nil if parsing fails, or we got an empty input.
        return AST.RegoValue(booleanLiteral: (try? Yams.load(yaml: rawYAML)) != nil)
    }

    /// Serializes the input term to YAML.
    public static func yamlMarshal(ctx: BuiltinContext, args: [AST.RegoValue]) async throws -> AST.RegoValue {
        guard args.count == 1 else {
            throw Rego.BuiltinError.argumentCountMismatch(got: args.count, want: 1)
        }

        let encoder = YAMLEncoder()
        let data = try encoder.encode(args[0])

        return AST.RegoValue(stringLiteral: data)
    }

    /// Deserializes the input YAML string to a term.
    public static func yamlUnmarshal(ctx: BuiltinContext, args: [AST.RegoValue]) async throws -> AST.RegoValue {
        guard args.count == 1 else {
            throw Rego.BuiltinError.argumentCountMismatch(got: args.count, want: 1)
        }

        guard case .string(let rawYAML) = args[0] else {
            throw BuiltinError.argumentTypeMismatch(arg: "x", got: args[0].typeName, want: "string")
        }

        let decoder = YAMLDecoder()
        return try decoder.decode(AST.RegoValue.self, from: rawYAML)
    }
}
