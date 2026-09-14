import AST
import AsyncHTTPClient
import Config
import Foundation
import Logging
import NIOConcurrencyHelpers
import Rego
import Testing

@testable import Runtime

// MARK: - Test double

/// An in-memory decision logger for verifying the Runtime's `decision()` ->
/// logger wiring without any network. Because the Runtime builds loggers from
/// the `decisionLoggers` type list (we can't reach the instance it creates),
/// events are recorded into a shared static sink the test can inspect.
final class RecordingDecisionLogger: OPA.DecisionLogger, @unchecked Sendable {
    /// Shared sink for events across whichever instance the Runtime builds.
    static let received = NIOLockedValueBox<[OPA.DecisionLogEvent]>([])

    static func reset() { received.withLockedValue { $0 = [] } }

    init(
        config: OPA.DecisionLogsConfig,
        service: OPA.ServiceConfig?,
        httpClientConfig: HTTPClient.Configuration?,
        httpClientCache: OPA.HTTPClientCache?,
        logger: Logger,
        startingEvents: [OPA.DecisionLogEvent]
    ) throws {
        Self.received.withLockedValue { $0.append(contentsOf: startingEvents) }
    }

    static func compatibleWithConfig(_ config: OPA.DecisionLogsConfig) -> Bool { true }
    func log(_ event: OPA.DecisionLogEvent) async { Self.received.withLockedValue { $0.append(event) } }
    func run() async {
        while !Task.isCancelled {
            do { try await Task.sleep(for: .seconds(3600)) } catch { break }
        }
    }
    func drain() async -> [OPA.DecisionLogEvent] {
        Self.received.withLockedValue { events in
            let out = events
            events.removeAll()
            return out
        }
    }
    func flush() async {}
}

// MARK: - Runtime integration (no network — disk bundles)

@Suite("Runtime decision logging (disk)", .serialized)
struct RuntimeDecisionLoggingTests {
    /// Writes the example bundle to a temp dir and returns (tempDir, config JSON
    /// with `{TEMP}` substituted).
    private func makeBundleAndConfig(decisionLogs: String) throws -> (URL, OPA.Config) {
        let tempDir = try makeTempDir()
        let testBundle = try makeExampleBundle()
        let bundleURL = tempDir.appendingPathComponent("bundle.tar.gz")
        try OPA.Bundle.encodeToTarball(bundle: testBundle).write(to: bundleURL)

        let json = #"""
            {
              "services": {
                "logs": {"url": "http://127.0.0.1:1/"}
              },
              "bundles": {
                "test": {"resource": "file:///{TEMP}/bundle.tar.gz"}
              },
              "decision_logs": \#(decisionLogs)
            }
            """#
            .replacingOccurrences(of: "{TEMP}", with: tempDir.path())
        let config = try JSONDecoder().decode(OPA.Config.self, from: Data(json.utf8))
        return (tempDir, config)
    }

    @Test("console logging emits a decision event line")
    func testConsoleLogging() async throws {
        let (tempDir, config) = try makeBundleAndConfig(decisionLogs: #"{"console": true}"#)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let capture = CapturingLogHandler()
        let logger = Logger(label: "test.rt.console") { _ in capture }
        let rt = try OPA.Runtime(config: config, logger: logger)

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }
        _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(2))

        _ = try await rt.decision("data/foo/hello", input: ["user": "alice"])

        let ok = await waitUntil {
            capture.messages(atLeast: .info).contains { $0.contains("\"decision_id\"") }
        }
        #expect(ok)
        let jsonLine = capture.messages(atLeast: .info).first { $0.contains("\"decision_id\"") } ?? ""
        #expect(jsonLine.contains("\"path\":\"foo\\/hello\"") || jsonLine.contains("\"path\":\"foo/hello\""))
    }

    @Test("custom logger selected from the type list receives decision events")
    func testCustomLoggerViaRegistry() async throws {
        RecordingDecisionLogger.reset()
        // A service is configured so an decision logger is selected. The custom
        // recorder matches `compatibleWithConfig` and never touches the network.
        let (tempDir, config) = try makeBundleAndConfig(decisionLogs: #"{"service": "logs"}"#)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let rt = try OPA.Runtime(config: config, decisionLoggers: [RecordingDecisionLogger.self])

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }
        _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(2))

        _ = try await rt.decision("data/foo/hello", input: ["user": "bob"])

        let ok = await waitUntil {
            RecordingDecisionLogger.received.withLockedValue { !$0.isEmpty }
        }
        #expect(ok)
        let event = RecordingDecisionLogger.received.withLockedValue { $0.first }
        #expect(event?.path == "foo/hello")
        #expect(event?.input == ["user": "bob"])
        #expect(event?.result == 1)  // {"result": 1} unwrapped
        // Bundle revision should be captured.
        #expect(event?.bundles?["test"] != nil)
    }

    @Test("no decision_logs config means no logging / no event")
    func testNoDecisionLogs() async throws {
        RecordingDecisionLogger.reset()
        let tempDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let testBundle = try makeExampleBundle()
        let bundleURL = tempDir.appendingPathComponent("bundle.tar.gz")
        try OPA.Bundle.encodeToTarball(bundle: testBundle).write(to: bundleURL)
        let json = #"""
            {"bundles": {"test": {"resource": "file:///{TEMP}/bundle.tar.gz"}}}
            """#
            .replacingOccurrences(of: "{TEMP}", with: tempDir.path())
        let config = try JSONDecoder().decode(OPA.Config.self, from: Data(json.utf8))

        // With no decision_logs section, the type list is never consulted.
        let rt = try OPA.Runtime(config: config, decisionLoggers: [RecordingDecisionLogger.self])
        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }
        _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(2))

        let dr = try await rt.decision("data/foo/hello", input: nil)
        #expect(dr.result.first == ["result": 1])
        // Give any (erroneous) async logging a chance, then confirm nothing logged.
        try? await Task.sleep(for: .milliseconds(200))
        #expect(RecordingDecisionLogger.received.withLockedValue { $0.isEmpty })
    }
}
