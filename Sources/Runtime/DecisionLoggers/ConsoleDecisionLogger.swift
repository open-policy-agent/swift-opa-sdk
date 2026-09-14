import AsyncHTTPClient
import Config
import Foundation
import Logging
import Rego

extension OPA {
    /// A ``DecisionLogger`` that writes each event to a swift-log ``Logger`` as
    /// a single JSON line, mirroring OPA's `console` decision logging.
    ///
    /// Console logging is independent of service uploads: in the ``OPA/Runtime``
    /// it is gated by `decision_logs.console` and applied inline, reusing
    /// ``emit(_:using:)``. This type additionally lets a caller use console
    /// logging standalone (no service, no buffering) — ``run()`` and ``drain()``
    /// are no-ops.
    public final class ConsoleDecisionLogger: DecisionLogger {
        private let logger: Logger

        public init(
            config: OPA.DecisionLogsConfig,
            service: OPA.ServiceConfig?,
            httpClientConfig: HTTPClient.Configuration?,
            httpClientCache: OPA.HTTPClientCache?,
            logger: Logger,
            startingEvents: [OPA.DecisionLogEvent]
        ) throws {
            self.logger = logger
            // Any starting events are logged immediately. Console logging is
            // stateless, so there is nothing to buffer.
            for event in startingEvents {
                Self.emit(event, using: logger)
            }
        }

        /// Compatible when console logging is requested without a service to
        /// upload to (the console-only case).
        public static func compatibleWithConfig(_ config: OPA.DecisionLogsConfig) -> Bool {
            config.consoleLogs && config.service.isEmpty
        }

        public func log(_ event: OPA.DecisionLogEvent) async {
            Self.emit(event, using: self.logger)
        }

        public func run() async {
            // Nothing to upload. Idle until cancelled.
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(3600))
                } catch {
                    break
                }
            }
        }

        public func drain() async -> [OPA.DecisionLogEvent] { [] }

        /// Emits a single event as a JSON line via `logger` at info level.
        /// Used both by this logger and by the Runtime's inline console path.
        public static func emit(_ event: OPA.DecisionLogEvent, using logger: Logger) {
            let line: String
            do {
                let data = try Self.encoder.encode(event)
                line = String(decoding: data, as: UTF8.self)
            } catch {
                logger.error("failed to encode decision log event: \(error)")
                return
            }
            logger.info("\(line)")
        }

        /// Shared encoder producing OPA-compatible JSON (ISO8601 timestamps).
        private static let encoder: JSONEncoder = {
            let e = JSONEncoder()
            e.dateEncodingStrategy = .iso8601
            e.outputFormatting = [.sortedKeys]
            return e
        }()
    }
}
