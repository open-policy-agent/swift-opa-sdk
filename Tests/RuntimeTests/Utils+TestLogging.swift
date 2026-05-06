import Foundation
import Logging

/// One-shot `LoggingSystem.bootstrap` call for the test target.
///
/// The swift-opa runtime and bundle loaders log at `info` by default,
/// which produces a lot of noise in test output. This helper reroutes
/// swift-log output through ``SwiftLogNoOpLogHandler`` (silent) unless
/// the `SWIFT_OPA_TEST_LOG` environment variable is set.
///
/// Accepted values for `SWIFT_OPA_TEST_LOG`:
/// - Unset / empty / `0` / `false` / `no` / `off` / `silent`: silent (default)
/// - `1` / `true` / `yes` / `on`: `info` level
/// - `trace` / `debug` / `info` / `warning` / `error` / `critical`: matching level
/// - Any other non-empty value: `info` level
///
/// ## Mechanics
///
/// `LoggingSystem.bootstrap` may only be called once per process. This
/// helper uses a private `static let` (which Swift guarantees is lazy
/// and thread-safe) to idempotently register the handler. Call
/// ``TestLogging/ensureBootstrapped()`` from any test helper that may
/// run before the first `Logger(label:)` evaluation.
public enum TestLogging {
    /// Ensures the test-target logging handler is installed. Safe to
    /// call from multiple threads and multiple test suites — only the
    /// first call does any work.
    public static func ensureBootstrapped() {
        _ = bootstrap
    }

    private static let bootstrap: Void = {
        let level = readLogLevel()
        LoggingSystem.bootstrap { label in
            guard let level else {
                return SwiftLogNoOpLogHandler()
            }
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = level
            return handler
        }
    }()

    private static func readLogLevel() -> Logger.Level? {
        let raw =
            ProcessInfo.processInfo.environment["SWIFT_OPA_TEST_LOG"]?
            .lowercased() ?? ""
        switch raw {
        case "", "0", "false", "no", "off", "silent", "none":
            return nil
        case "1", "true", "yes", "on":
            return .info
        case "trace": return .trace
        case "debug": return .debug
        case "info": return .info
        case "warning", "warn": return .warning
        case "error": return .error
        case "critical": return .critical
        default:
            // Any other non-empty value: default to info rather than
            // silently ignoring the user's intent to see logs.
            return .info
        }
    }
}
