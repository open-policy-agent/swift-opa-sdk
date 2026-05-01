import AST
import Foundation
import Rego
import Runtime
import Testing

public func makeTempDir() throws -> URL {
    let tempDir = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)

    try FileManager.default.createDirectory(
        at: tempDir,
        withIntermediateDirectories: true
    )

    guard FileManager.default.isWritableFile(atPath: tempDir.path) else {
        throw NSError(
            domain: "TestUtils",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Temp directory is not writable: \(tempDir.path)"]
        )
    }

    return tempDir
}

public func makeExampleBundle(
    manifest: OPA.Manifest? = nil,
    planFiles: [BundleFile]? = nil,
    regoFiles: [BundleFile]? = nil,
    data: AST.RegoValue? = nil
) throws -> OPA.Bundle {
    let id = UUID().uuidString
    let manifest = manifest ?? OPA.Manifest(revision: UUID().uuidString, roots: ["/\(id)"])
    let planFiles =
        planFiles ?? [
            Rego.BundleFile(
                url: URL(string: "/plan.json")!,
                data: #"""
                    {
                    "static":{"strings":[{"value":"result"},{"value":"1"}],"files":[{"value":"bar.rego"}]},
                    "plans":{"plans":[{"name":"foo/hello","blocks":[{"stmts":[
                    {"type":"CallStmt","stmt":{"func":"g0.data.foo.hello","args":[{"type":"local","value":0},{"type":"local","value":1}],"result":2,"file":0,"col":0,"row":0}},
                    {"type":"AssignVarStmt","stmt":{"source":{"type":"local","value":2},"target":3,"file":0,"col":0,"row":0}},
                    {"type":"MakeObjectStmt","stmt":{"target":4,"file":0,"col":0,"row":0}},
                    {"type":"ObjectInsertStmt","stmt":{"key":{"type":"string_index","value":0},"value":{"type":"local","value":3},"object":4,"file":0,"col":0,"row":0}},
                    {"type":"ResultSetAddStmt","stmt":{"value":4,"file":0,"col":0,"row":0}}]}]}]},
                    "funcs":{"funcs":[{"name":"g0.data.foo.hello","params":[0,1],"return":2,"blocks":[{"stmts":[{"type":"ResetLocalStmt","stmt":{"target":3,"file":0,"col":1,"row":3}},{"type":"MakeNumberRefStmt","stmt":{"Index":1,"target":4,"file":0,"col":1,"row":3}},{"type":"AssignVarOnceStmt","stmt":{"source":{"type":"local","value":4},"target":3,"file":0,"col":1,"row":3}}]},{"stmts":[{"type":"IsDefinedStmt","stmt":{"source":3,"file":0,"col":1,"row":3}},{"type":"AssignVarOnceStmt","stmt":{"source":{"type":"local","value":3},"target":2,"file":0,"col":1,"row":3}}]},{"stmts":[{"type":"ReturnLocalStmt","stmt":{"source":2,"file":0,"col":1,"row":3}}]}],"path":["g0","foo","hello"]}]}
                    }
                    """#.data(using: .utf8)!
            )
        ]
    let regoFiles =
        regoFiles ?? [
            Rego.BundleFile(
                url: URL(string: "/\(id)/foo/bar.rego")!,
                data: "package foo\n\nhello=1".data(using: .utf8)!
            )
        ]
    let data =
        data ?? [
            "\(id)": [
                "foo": [
                    "bar": 1,
                    "baz": "qux",
                ]
            ]
        ]
    return try OPA.Bundle(manifest: manifest, planFiles: planFiles, regoFiles: regoFiles, data: data)
}

/// Polls until the named bundle appears in the runtime's storage and
/// `predicate` returns `true`, or the timeout expires. When no predicate
/// is provided, this degrades into an "is bundle loaded?" check.
public func waitForBundleLoad(
    rt: OPA.Runtime,
    name: String,
    timeout: Duration = .seconds(30),
    pollInterval: Duration = .milliseconds(100),
    where predicate: (@Sendable (Result<OPA.Bundle, any Swift.Error>) -> Bool)? = nil
) async -> Result<OPA.Bundle, any Swift.Error>? {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        if let result = await rt.bundleStorage[name],
            predicate?(result) ?? true
        {
            return result
        }
        try? await Task.sleep(for: pollInterval)
    }
    return nil
}

/// Unwrap a successful bundle result or fail the test.
public func requireBundleLoadSuccess(
    _ result: Result<OPA.Bundle, Error>,
    context: String = ""
) throws -> OPA.Bundle {
    guard case .success(let bundle) = result else {
        let msg = "Expected .success\(context.isEmpty ? "" : " \(context)"), got \(result)"
        Issue.record(Comment(rawValue: msg))
        throw BundleResultError.unexpectedFailure(message: msg)
    }
    return bundle
}

/// Unwrap a failure bundle result or fail the test.
public func requireBundleLoadFailure(
    _ result: Result<OPA.Bundle, Error>,
    context: String = ""
) throws -> Error {
    guard case .failure(let error) = result else {
        let msg = "Expected .failure\(context.isEmpty ? "" : " \(context)"), got \(result)"
        Issue.record(Comment(rawValue: msg))
        throw BundleResultError.unexpectedFailure(message: msg)
    }
    return error
}

public enum BundleResultError: Error {
    case unexpectedFailure(message: String)
}

/// Build an OPA config JSON pointing at the given ETag test server.
public func makeETagTestConfig(
    baseURL: String, bundleName: String = "test", resourcePath: String = "/bundles/test.tar.gz"
) -> String {
    """
    {
      "services": {
        "test-svc": {"url": "\(baseURL)"}
      },
      "bundles": {
        "\(bundleName)": {
          "service": "test-svc",
          "resource": "\(resourcePath)"
        }
      }
    }
    """
}

/// Build a config with short polling intervals for runtime integration tests.
public func makeETagTestConfigWithPolling(
    baseURL: String, bundleName: String = "test", resourcePath: String = "/bundles/test.tar.gz"
) -> String {
    """
    {
      "services": {
        "test-svc": {"url": "\(baseURL)"}
      },
      "bundles": {
        "\(bundleName)": {
          "service": "test-svc",
          "resource": "\(resourcePath)",
          "polling": {
            "min_delay_seconds": 1,
            "max_delay_seconds": 1
          }
        }
      }
    }
    """
}

/// Build a config with long-polling enabled for loader-level tests.
public func makeETagTestConfigWithLongPolling(
    baseURL: String,
    bundleName: String = "test",
    resourcePath: String = "/bundles/test.tar.gz",
    minDelaySeconds: Int = 1,
    maxDelaySeconds: Int = 1,
    longPollingTimeoutSeconds: Int = 30
) -> String {
    """
    {
      "services": {
        "test-svc": {"url": "\(baseURL)"}
      },
      "bundles": {
        "\(bundleName)": {
          "service": "test-svc",
          "resource": "\(resourcePath)",
          "polling": {
            "min_delay_seconds": \(minDelaySeconds),
            "max_delay_seconds": \(maxDelaySeconds),
            "long_polling_timeout_seconds": \(longPollingTimeoutSeconds)
          }
        }
      }
    }
    """
}

/// Construct a `RESTClientBundleLoader` from a config JSON string.
public func makeRESTClientBundleLoader(
    configJSON: String,
    bundleName: String = "test",
    etag: String? = nil
) throws -> OPA.RESTClientBundleLoader {
    let config = try JSONDecoder().decode(OPA.Config.self, from: configJSON.data(using: .utf8)!)
    return try OPA.RESTClientBundleLoader(
        config: config,
        bundleResourceName: bundleName,
        etag: etag,
        headers: nil,
        httpClientConfig: nil
    )
}
