import Foundation
import Rego

// SDKBuiltinFuncs is a local wrapper around the Rego builtin functions we provide
// in this package. The functions are implemented in files following the
// upstream Go topdown file organization to help better keep the 1:1 mapping.
// Each function needs to be registered in the sdkDefaultBuiltins.
public enum SDKBuiltinFuncs {

}

extension SDKBuiltinFuncs {
    /// The default set of builtins for this library.
    public static var sdkDefaultBuiltins: [String: Rego.BuiltinImpl] {
        return [:]
    }

    /// Names of all SDK-provided builtins.
    public static var names: Set<String> { Set(sdkDefaultBuiltins.keys) }

    /// Returns the names of all SDK-provided builtins.
    public static func getSupportedBuiltinNames() -> [String] { Array(sdkDefaultBuiltins.keys) }

    /// Returns the implementation for `name`, or `nil` if the SDK does not provide it.
    public static subscript(name: String) -> Rego.BuiltinImpl? { sdkDefaultBuiltins[name] }

    /// The async-only builtins in the SDK default set, as a typed dictionary.
    ///
    /// Currently empty, as all SDK builtins are synchronous. Provided for API symmetry
    /// with ``sdkDefaultSyncBuiltins``.
    public static var sdkDefaultAsyncBuiltins: [String: Rego.AsyncBuiltin] {
        sdkDefaultBuiltins.compactMapValues {
            guard case .asyncOnly(let f) = $0 else { return nil }
            return f
        }
    }

    /// The synchronous builtins in the SDK default set, as a typed dictionary.
    public static var sdkDefaultSyncBuiltins: [String: Rego.SyncBuiltin] {
        sdkDefaultBuiltins.compactMapValues {
            guard case .sync(let f) = $0 else { return nil }
            return f
        }
    }
}
