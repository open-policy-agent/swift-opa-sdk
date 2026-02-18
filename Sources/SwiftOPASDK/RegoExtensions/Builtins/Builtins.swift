import Foundation
import Rego

// SDKBuiltinFuncs is a local wrapper around the Rego builtin functions we provide
// in this package. The functions are implemented in files following the
// upstream Go topdown file organization to help better keep the 1:1 mapping.
// Each function needs to be registered in the sdkDefaultBuiltins.
public enum SDKBuiltinFuncs {

}

extension SDKBuiltinFuncs {
    internal static var sdkDefaultBuiltins: [String: Rego.Builtin] {
        return [
            "yaml.is_valid": SDKBuiltinFuncs.yamlIsValid,
            "yaml.marshal": SDKBuiltinFuncs.yamlMarshal,
            "yaml.unmarshal": SDKBuiltinFuncs.yamlUnmarshal,
        ]
    }

    /// Returns the merged set of builtins for this library and Swift OPA.
    public static func getSDKDefaultBuiltins() -> [String: Rego.Builtin] {
        let opaDefaultRegistry = BuiltinRegistry.defaultRegistry
        let opaDefaultBuiltins = BuiltinRegistry.getSupportedBuiltinNames().reduce(into: [String: Builtin]()) {
            dict, key in
            dict[key] = opaDefaultRegistry[key]
        }

        // Merge with upstream Swift OPA's builtins, keeping ours on conflicts.
        return SDKBuiltinFuncs.sdkDefaultBuiltins.merging(opaDefaultBuiltins, uniquingKeysWith: { sdk, _ in sdk })
    }
}
