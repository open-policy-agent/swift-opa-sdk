import AST
import Foundation
import Logging
import Rego
import Runtime
import Testing

public func makeTempDir() throws -> URL {
    TestLogging.ensureBootstrapped()
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
    TestLogging.ensureBootstrapped()
    let id = UUID().uuidString
    let manifest = manifest ?? OPA.Manifest(revision: UUID().uuidString, roots: ["/\(id)", "foo"])
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

/// Polls until the named bundle reaches an observable poll outcome and
/// `predicate` returns `true`, or the timeout expires. Returns a
/// ``OPA/BundleUpdate`` synthesized from the runtime's `activeBundles()`
/// snapshot: `.downloaded` when a bundle is active, `.failed` when only an error
/// is recorded, and `nil` while nothing has been observed yet. When no predicate
/// is provided, this degrades into an "is there any outcome yet?" check.
///
/// - Important: once a bundle has been activated it always reports
///   `.downloaded` here, because a failing refresh keeps the bundle live. To
///   wait for a failure recorded *beside* a still-live bundle, use
///   ``waitForBundleError`` instead — a `.failed` predicate would never match
///   and would block for the full timeout.
public func waitForBundleLoad(
    rt: OPA.Runtime,
    name: String,
    timeout: Duration = .seconds(30),
    pollInterval: Duration = .milliseconds(100),
    where predicate: (@Sendable (OPA.BundleUpdate) -> Bool)? = nil
) async -> OPA.BundleUpdate? {
    TestLogging.ensureBootstrapped()
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        if let update = bundleUpdateSnapshot(rt: rt, name: name),
            predicate?(update) ?? true
        {
            return update
        }
        try? await Task.sleep(for: pollInterval)
    }
    return nil
}

/// Synthesizes a ``OPA/BundleUpdate`` for `name` from the runtime's current
/// status snapshot: `.downloaded` when a bundle is active, `.failed` when only
/// an error is recorded, `nil` when nothing has been observed yet.
private func bundleUpdateSnapshot(rt: OPA.Runtime, name: String) -> OPA.BundleUpdate? {
    guard let status = rt.activeBundles()[name] else { return nil }
    let meta = status.metadata
    if let bundle = status.bundle {
        return .downloaded(bundle, etag: meta.etag, size: meta.size)
    }
    if meta.code != nil {
        return .failed(
            BundleFetchError(
                code: .bundleLoadError,
                message: meta.message ?? "bundle \(name) failed to load",
                httpStatus: meta.httpCode))
    }
    return nil
}

/// Polls until the named bundle has an error recorded in its status metadata
/// (its most recent poll failed), or the timeout expires. Unlike
/// ``waitForBundleLoad``, this surfaces a failure recorded *beside* a
/// still-live bundle.
public func waitForBundleError(
    rt: OPA.Runtime,
    name: String,
    timeout: Duration = .seconds(30),
    pollInterval: Duration = .milliseconds(100)
) async -> OPA.BundleStatusMetadata? {
    TestLogging.ensureBootstrapped()
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        if let meta = rt.activeBundleMetadata()[name], meta.code != nil { return meta }
        try? await Task.sleep(for: pollInterval)
    }
    return nil
}

/// Unwrap a successful (downloaded) bundle outcome or fail the test.
public func requireBundleLoadSuccess(
    _ update: OPA.BundleUpdate,
    context: String = ""
) throws -> OPA.Bundle {
    guard case .downloaded(let bundle, _, _) = update else {
        let msg = "Expected .downloaded\(context.isEmpty ? "" : " \(context)"), got \(update)"
        Issue.record(Comment(rawValue: msg))
        throw BundleResultError.unexpectedFailure(message: msg)
    }
    return bundle
}

/// Unwrap a failed bundle outcome or fail the test.
public func requireBundleLoadFailure(
    _ update: OPA.BundleUpdate,
    context: String = ""
) throws -> Error {
    guard case .failed(let error) = update else {
        let msg = "Expected .failed\(context.isEmpty ? "" : " \(context)"), got \(update)"
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
    etag: String? = nil,
    httpClientConfig: OPA.HTTPClientConfigSource? = nil,
    logger: Logger? = nil
) throws -> OPA.RESTClientBundleLoader {
    TestLogging.ensureBootstrapped()
    let config = try JSONDecoder().decode(OPA.Config.self, from: configJSON.data(using: .utf8)!)
    return try OPA.RESTClientBundleLoader(
        config: config,
        bundleResourceName: bundleName,
        etag: etag,
        headers: nil,
        httpClientConfig: httpClientConfig,
        logger: logger
    )
}
