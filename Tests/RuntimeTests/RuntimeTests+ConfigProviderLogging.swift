import AST
import Foundation
import Logging
import Rego
import Testing

@testable import Runtime

/// Tests that the Runtime makes ConfigProvider setup/load failures visible in
/// the logs, rather than failing silently.
@Suite("Runtime ConfigProvider logging")
struct RuntimeConfigProviderLoggingTests {

    /// An injected ConfigProvider whose `load()` always fails with a
    /// distinctive message, so a test can find it in the captured logs.
    struct AlwaysFailingConfigProvider: OPA.ConfigProvider {
        let failureMessage: String

        init(config: OPA.Config, logger: Logger?) throws {
            self.failureMessage = "unused"
        }

        init(failureMessage: String) {
            self.failureMessage = failureMessage
        }

        func load() async -> Result<OPA.Config, any Swift.Error> {
            .failure(RuntimeError(code: .internalError, message: failureMessage))
        }
    }

    @Test("A failing config provider load() is logged at .error")
    func loadFailureIsLoggedAtError() async throws {
        let marker = "load-failed-\(UUID().uuidString)"
        let capture = CapturingLogHandler()
        let logger = Logger(label: "test.runtime-config-logging") { _ in capture }

        let config = try JSONDecoder().decode(OPA.Config.self, from: Data("{}".utf8))
        let runtime = try OPA.Runtime(
            config: config,
            configProvider: AlwaysFailingConfigProvider(failureMessage: marker),
            logger: logger)

        // The first load() runs immediately, before the loop sleeps, so the
        // error is logged promptly. Poll briefly, then tear the worker down.
        let task = Task { try? await runtime.run() }
        defer { task.cancel() }

        var found = false
        for _ in 0..<200 {
            let errors = capture.messages(atLeast: .error)
            if errors.contains(where: { $0.contains(marker) }) {
                found = true
                break
            }
            try await Task.sleep(for: .milliseconds(10))
        }
        task.cancel()

        #expect(found, "expected an .error log mentioning the load failure \(marker)")
    }

    @Test("A failed auto-built DiscoveryConfigProvider construction is logged at .error")
    func constructionFailureIsLoggedAtError() async throws {
        // Discovery section is present (so the Runtime tries to auto-build a
        // DiscoveryConfigProvider), but no bundle loaders are supplied, so the
        // provider's init throws with "no compatible loader".
        let configJSON = """
            {
                "services": {},
                "discovery": {
                    "service": "missing-service",
                    "resource": "/discovery"
                }
            }
            """
        let config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))

        let capture = CapturingLogHandler()
        let logger = Logger(label: "test.runtime-config-logging") { _ in capture }

        #expect(throws: (any Error).self) {
            _ = try OPA.Runtime(config: config, bundleLoaders: [], logger: logger)
        }

        let errors = capture.messages(atLeast: .error)
        #expect(
            errors.contains { $0.contains("Failed to construct DiscoveryConfigProvider") },
            "expected an .error log about the failed provider construction, got \(errors)")
    }
}
