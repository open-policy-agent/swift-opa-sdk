import AsyncHTTPClient
import Config
import Foundation
import Logging
import Rego

extension OPA {
    /// A sink for decision log events.
    ///
    /// A `DecisionLogger` buffers events handed to it via ``log(_:)`` and, for
    /// service-backed implementations, periodically uploads them from its
    /// ``run()`` loop. Implementations mirror the ``BundleLoader`` pattern: a
    /// config-driven initializer plus a static ``compatibleWithConfig(_:)``
    /// check so the ``OPA/Runtime`` can select the right implementation for a
    /// given `decision_logs` configuration.
    ///
    /// ## Independence from the Runtime
    ///
    /// A logger is fully usable on its own: construct it from a
    /// ``OPA/DecisionLogsConfig`` (+ ``OPA/ServiceConfig``), start its loop with
    /// `Task { await logger.run() }`, and feed it events via `await logger.log(event)`.
    /// Drop/mask policy evaluation and console emission both live in
    /// ``OPA/Runtime/decision(_:input:decisionID:)`` and are *not* part of this
    /// protocol, keeping the surface small: a standalone caller is free to build
    /// and mask events however it likes.
    ///
    /// ## Hot-swapping
    ///
    /// To support lossless reconfiguration, a replacement logger can be started
    /// with events drained from its predecessor via `startingEvents:` at init, and
    /// ``drain()`` removes and returns any buffered events from a logger that is
    /// being retired. This surface is expected to evolve.
    public protocol DecisionLogger: Sendable {
        /// Builds a logger from resolved decision-logs configuration.
        ///
        /// - Parameters:
        ///   - config: The resolved ``OPA/DecisionLogsConfig``.
        ///   - service: The resolved upload service, or `nil` for no uploads.
        ///   - httpClientConfig: HTTP client configuration for uploads.
        ///   - httpClientCache: Shared cache of pooled HTTP clients, keyed by
        ///     service. Pass `nil` to use an ephemeral one-off client per
        ///     upload (the standalone, no-`Runtime` case).
        ///   - logger: A swift-log logger for diagnostics.
        ///   - startingEvents: Events to pre-load into the buffer (for hot-swap).
        init(
            config: OPA.DecisionLogsConfig,
            service: OPA.ServiceConfig?,
            httpClientConfig: HTTPClient.Configuration?,
            httpClientCache: OPA.HTTPClientCache?,
            logger: Logger,
            startingEvents: [OPA.DecisionLogEvent]
        ) throws

        /// Compatibility check against the current OPA config.
        static func compatibleWithConfig(_ config: OPA.DecisionLogsConfig) -> Bool

        /// Enqueues an event. Non-blocking: never performs network I/O and
        /// never throws. On buffer overflow the implementation drops events
        /// per its buffering policy and records the drop.
        func log(_ event: OPA.DecisionLogEvent) async

        /// Runs the upload loop until the surrounding task is cancelled, then
        /// performs a best-effort final drain + upload before returning.
        func run() async

        /// Removes and returns all currently buffered events, for hand-off to
        /// a replacement logger.
        func drain() async -> [OPA.DecisionLogEvent]
    }
}
