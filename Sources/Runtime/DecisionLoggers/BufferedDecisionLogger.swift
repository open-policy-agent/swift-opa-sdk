import AsyncHTTPClient
import Config
import Foundation
import Logging
import Rego

extension OPA {
    /// The service-backed decision logger: a ``DecisionLogBuffer`` drained and
    /// uploaded by a background ``DecisionLogUploadPump``.
    ///
    /// The `size` vs `event` distinction is no longer a type distinction — it is
    /// a ``BufferingPolicy`` derived from the config at init time. `size` is the
    /// byte-bounded "bounded memory" mode (OPA's default) with optional
    /// `max_decisions_per_second` rate limiting; `event` is the count-bounded
    /// "as-fast-as-possible" mode.
    ///
    /// A logger is usable standalone: construct it, start `Task { await
    /// logger.run() }`, and feed it events via `await logger.log(event)`. The
    /// drop/mask policy evaluation and console emission that normally precede
    /// logging live in ``OPA/Runtime/decision(_:input:decisionID:)``, so this
    /// type stays a plain buffered sink.
    public final class BufferedDecisionLogger: DecisionLogger {
        private let buffer: DecisionLogBuffer
        private let pump: DecisionLogUploadPump

        public init(
            config: OPA.DecisionLogsConfig,
            service: OPA.ServiceConfig?,
            httpClientConfig: HTTPClient.Configuration?,
            httpClientCache: OPA.HTTPClientCache?,
            logger: Logger,
            startingEvents: [OPA.DecisionLogEvent]
        ) throws {
            let reporting = config.reporting

            let uploader: OPA.DecisionLogUploader?
            if let service {
                uploader = try OPA.DecisionLogUploader(
                    service: service,
                    serviceName: config.service,
                    resource: config.resource ?? defaultResourcePath,
                    uploadSizeLimitBytes: reporting.uploadSizeLimitBytes ?? defaultUploadSizeLimitBytes,
                    httpClientConfig: httpClientConfig,
                    httpClientCache: httpClientCache,
                    logger: logger
                )
            } else {
                uploader = nil
            }

            self.buffer = DecisionLogBuffer(
                policy: Self.bufferingPolicy(from: reporting),
                logger: logger,
                startingEvents: startingEvents
            )
            self.pump = DecisionLogUploadPump(
                buffer: buffer,
                uploader: uploader,
                minDelaySeconds: reporting.minDelaySeconds ?? defaultMinDelaySeconds,
                maxDelaySeconds: reporting.maxDelaySeconds ?? defaultMaxDelaySeconds,
                logger: logger
            )
        }

        /// Selected whenever a service is configured to upload to. The buffer
        /// type is handled internally via ``BufferingPolicy``, so it no longer
        /// participates in logger selection.
        public static func compatibleWithConfig(_ config: OPA.DecisionLogsConfig) -> Bool {
            !config.service.isEmpty
        }

        public func log(_ event: OPA.DecisionLogEvent) async {
            if buffer.append(event) { pump.signal() }
        }

        public func run() async { await pump.run() }

        public func drain() async -> [OPA.DecisionLogEvent] {
            buffer.events(in: buffer.takeBatch())
        }

        /// Derives the buffering policy from the resolved reporting config.
        private static func bufferingPolicy(from reporting: OPA.ReportingConfig) -> BufferingPolicy {
            if reporting.bufferType == sizeBufferType {
                return .size(
                    maxBytes: reporting.bufferSizeLimitBytes ?? defaultBufferSizeLimitBytes,
                    maxDecisionsPerSecond: reporting.maxDecisionsPerSecond)
            }
            return .event(maxEvents: Int(reporting.bufferSizeLimitEvents ?? defaultBufferSizeLimitEvents))
        }

        /// Number of events currently buffered (diagnostics / testing).
        public var bufferedCount: Int { buffer.count }
        /// Number of events dropped so far (diagnostics / testing).
        public var droppedCount: Int { buffer.droppedCount }
        /// Approximate serialized size of the buffered events (diagnostics /
        /// testing). Always 0 for event mode and for an unlimited size buffer.
        public var bufferedBytes: Int { buffer.bufferedBytes }
    }
}
