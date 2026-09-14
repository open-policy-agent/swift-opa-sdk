import Foundation
import Rego

// From: v1/plugins/logs/plugin.go

// MARK: - Constants

/// Minimum amount of time to wait following a failure (100 milliseconds).
public let minRetryDelay: Duration = .milliseconds(100)

public let defaultMinDelaySeconds: Int64 = 300
public let defaultMaxDelaySeconds: Int64 = 600
public let defaultBufferSizeLimitEvents: Int64 = 10_000
public let defaultUploadSizeLimitBytes: Int64 = 32_768  // 32KB limit
// A single event with a decision ID (69 bytes) + empty gzip file (21 bytes)
public let minUploadSizeLimitBytes: Int64 = 90
public let maxUploadSizeLimitBytes: Int64 = 4_294_967_296  // about 4GB
public let defaultBufferSizeLimitBytes: Int64 = 0  // unlimited
public let defaultMaskDecisionPath = "/system/log/mask"
public let defaultDropDecisionPath = "/system/log/drop"
public let logRateLimitExDropCounterName = "decision_logs_dropped_rate_limit_exceeded"
public let logBufferEventDropCounterName = "decision_logs_dropped_buffer_size_limit_exceeded"
public let logBufferSizeLimitExDropCounterName = "decision_logs_dropped_buffer_size_limit_bytes_exceeded"
public let logEncodingFailureCounterName = "decision_logs_encoding_failure"
public let defaultResourcePath = "/logs"
public let sizeBufferType = "size"
public let eventBufferType = "event"

// MARK: - DecisionLogsConfigError

public enum DecisionLogsConfigError: Error, CustomStringConvertible {
    case invalidPluginName(String)
    case invalidServiceName(String)
    case maxDelayLessThanMinDelay
    case missingMaxDelaySeconds
    case missingMinDelaySeconds
    case invalidTriggerMode(underlying: Error)
    case invalidBufferType(String)
    case bufferSizeLimitBytesNotSupportedForEventBuffer
    case bufferSizeLimitEventsNotSupportedForSizeBuffer
    case mutuallyExclusiveBufferSizeLimitBytesAndDecisionsPerSecond
    case bufferSizeLimitBytesMustBePositive
    case bufferSizeLimitEventsMustBePositive
    case invalidResourcePath(String, underlying: Error)

    public var description: String {
        switch self {
        case .invalidPluginName(let name):
            return "invalid plugin name \"\(name)\" in decision_logs"
        case .invalidServiceName(let name):
            return "invalid service name \"\(name)\" in decision_logs"
        case .maxDelayLessThanMinDelay:
            return "max reporting delay must be >= min reporting delay in decision_logs"
        case .missingMaxDelaySeconds:
            return "reporting configuration missing 'max_delay_seconds' in decision_logs"
        case .missingMinDelaySeconds:
            return "reporting configuration missing 'min_delay_seconds' in decision_logs"
        case .invalidTriggerMode(let underlying):
            return "invalid decision_log config: \(underlying)"
        case .invalidBufferType(let bufferType):
            return
                "invalid buffer type \"\(bufferType)\", expected \"\(eventBufferType)\" or \"\(sizeBufferType)\""
        case .bufferSizeLimitBytesNotSupportedForEventBuffer:
            return
                "invalid decision_log config, 'buffer_size_limit_bytes' isn't supported for the \(eventBufferType) buffer type"
        case .bufferSizeLimitEventsNotSupportedForSizeBuffer:
            return
                "invalid decision_log config, 'buffer_size_limit_events' isn't supported for the \(sizeBufferType) buffer type"
        case .mutuallyExclusiveBufferSizeLimitBytesAndDecisionsPerSecond:
            return
                "invalid decision_log config, specify either 'buffer_size_limit_bytes' or 'max_decisions_per_second'"
        case .bufferSizeLimitBytesMustBePositive:
            return "invalid decision_log config, 'buffer_size_limit_bytes' must be higher than 0"
        case .bufferSizeLimitEventsMustBePositive:
            return "invalid decision_log config, 'buffer_size_limit_entries' must be higher than 0"
        case .invalidResourcePath(let path, let underlying):
            return "invalid resource path \"\(path)\": \(underlying)"
        }
    }
}

extension OPA {
    // MARK: - ReportingConfig

    /// Represents configuration for the plugin's reporting behaviour.
    public struct ReportingConfig: Codable, Equatable, Sendable {
        /// Toggles how the buffer stores events.
        public let bufferType: String

        /// Max size of in-memory size buffer.
        public let bufferSizeLimitBytes: Int64?

        /// Max size of in-memory event channel buffer.
        public let bufferSizeLimitEvents: Int64?

        /// Max size of upload payload.
        public let uploadSizeLimitBytes: Int64?

        /// Min amount of time to wait between successful poll attempts.
        public let minDelaySeconds: Int64?

        /// Max amount of time to wait between poll attempts.
        public let maxDelaySeconds: Int64?

        /// Max number of decision logs to buffer per second.
        public let maxDecisionsPerSecond: Double?

        /// Trigger mode.
        public let trigger: TriggerMode?

        public init(
            bufferType: String = sizeBufferType,
            bufferSizeLimitBytes: Int64? = nil,
            bufferSizeLimitEvents: Int64? = nil,
            uploadSizeLimitBytes: Int64? = nil,
            minDelaySeconds: Int64? = nil,
            maxDelaySeconds: Int64? = nil,
            maxDecisionsPerSecond: Double? = nil,
            trigger: TriggerMode? = nil
        ) throws {
            self.bufferType = bufferType
            self.bufferSizeLimitBytes = bufferSizeLimitBytes
            self.bufferSizeLimitEvents = bufferSizeLimitEvents
            self.uploadSizeLimitBytes = uploadSizeLimitBytes
            self.minDelaySeconds = minDelaySeconds
            self.maxDelaySeconds = maxDelaySeconds
            self.maxDecisionsPerSecond = maxDecisionsPerSecond
            self.trigger = trigger
            try self.validate()
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.bufferType =
                try container.decodeIfPresent(String.self, forKey: .bufferType)
                ?? sizeBufferType
            self.bufferSizeLimitBytes = try container.decodeIfPresent(
                Int64.self, forKey: .bufferSizeLimitBytes)
            self.bufferSizeLimitEvents = try container.decodeIfPresent(
                Int64.self, forKey: .bufferSizeLimitEvents)
            self.uploadSizeLimitBytes = try container.decodeIfPresent(
                Int64.self, forKey: .uploadSizeLimitBytes)
            self.minDelaySeconds = try container.decodeIfPresent(
                Int64.self, forKey: .minDelaySeconds)
            self.maxDelaySeconds = try container.decodeIfPresent(
                Int64.self, forKey: .maxDelaySeconds)
            self.maxDecisionsPerSecond = try container.decodeIfPresent(
                Double.self, forKey: .maxDecisionsPerSecond)
            self.trigger = try container.decodeIfPresent(
                TriggerMode.self, forKey: .trigger)
            try self.validate()
        }

        // MARK: - Validation

        /// Validates struct-local constraints.
        public func validate() throws {
            // buffer type must be a known value
            guard bufferType == eventBufferType || bufferType == sizeBufferType else {
                throw DecisionLogsConfigError.invalidBufferType(bufferType)
            }

            // buffer type / limit compatibility
            if bufferType == eventBufferType && bufferSizeLimitBytes != nil {
                throw DecisionLogsConfigError.bufferSizeLimitBytesNotSupportedForEventBuffer
            }
            if bufferType == sizeBufferType && bufferSizeLimitEvents != nil {
                throw DecisionLogsConfigError.bufferSizeLimitEventsNotSupportedForSizeBuffer
            }

            // mutual exclusivity
            if bufferSizeLimitBytes != nil && maxDecisionsPerSecond != nil {
                throw DecisionLogsConfigError
                    .mutuallyExclusiveBufferSizeLimitBytesAndDecisionsPerSecond
            }

            // buffer size limit (bytes) must be positive when explicitly set
            if let limit = bufferSizeLimitBytes, limit <= 0 {
                throw DecisionLogsConfigError.bufferSizeLimitBytesMustBePositive
            }

            // buffer size limit (events) must be positive when explicitly set
            if let limit = bufferSizeLimitEvents, limit <= 0 {
                throw DecisionLogsConfigError.bufferSizeLimitEventsMustBePositive
            }

            // min/max delay: both provided, or neither
            switch (minDelaySeconds, maxDelaySeconds) {
            case (.some(let minVal), .some(let maxVal)):
                guard maxVal >= minVal else {
                    throw DecisionLogsConfigError.maxDelayLessThanMinDelay
                }
            case (.some, .none):
                throw DecisionLogsConfigError.missingMaxDelaySeconds
            case (.none, .some):
                throw DecisionLogsConfigError.missingMinDelaySeconds
            case (.none, .none):
                break
            }
        }

        enum CodingKeys: String, CodingKey {
            case bufferType = "buffer_type"
            case bufferSizeLimitBytes = "buffer_size_limit_bytes"
            case bufferSizeLimitEvents = "buffer_size_limit_events"
            case uploadSizeLimitBytes = "upload_size_limit_bytes"
            case minDelaySeconds = "min_delay_seconds"
            case maxDelaySeconds = "max_delay_seconds"
            case maxDecisionsPerSecond = "max_decisions_per_second"
            case trigger
        }
    }

    // MARK: - RequestContextConfig

    public struct RequestContextConfig: Codable, Equatable, Sendable {
        public let httpRequest: HTTPRequestContextConfig?

        public init(httpRequest: HTTPRequestContextConfig? = nil) {
            self.httpRequest = httpRequest
        }

        enum CodingKeys: String, CodingKey {
            case httpRequest = "http"
        }
    }

    // MARK: - HTTPRequestContextConfig

    public struct HTTPRequestContextConfig: Codable, Equatable, Sendable {
        public let headers: [String]?

        public init(headers: [String]? = nil) {
            self.headers = headers
        }

        enum CodingKeys: String, CodingKey {
            case headers
        }
    }

    // MARK: - DecisionLogsConfig

    /// Represents the plugin configuration.
    public struct DecisionLogsConfig: Codable, Equatable, Sendable {
        public let plugin: String?
        public let service: String
        public let partitionName: String?
        public let reporting: ReportingConfig
        public let requestContext: RequestContextConfig
        public let maskDecision: String
        public let dropDecision: String
        public let consoleLogs: Bool
        public let resource: String?
        public let ndBuiltinCache: Bool?

        public init(
            plugin: String? = nil,
            service: String = "",
            partitionName: String? = nil,
            reporting: ReportingConfig? = nil,
            requestContext: RequestContextConfig = RequestContextConfig(),
            maskDecision: String = defaultMaskDecisionPath,
            dropDecision: String = defaultDropDecisionPath,
            consoleLogs: Bool = false,
            resource: String? = nil,
            ndBuiltinCache: Bool? = nil
        ) throws {
            self.plugin = plugin
            self.service = service
            self.partitionName = partitionName
            self.reporting = try reporting ?? ReportingConfig()
            self.requestContext = requestContext
            self.maskDecision = maskDecision
            self.dropDecision = dropDecision
            self.consoleLogs = consoleLogs
            self.resource = resource
            self.ndBuiltinCache = ndBuiltinCache
            try self.validate()
        }

        enum CodingKeys: String, CodingKey {
            case plugin
            case service
            case partitionName = "partition_name"
            case reporting
            case requestContext = "request_context"
            case maskDecision = "mask_decision"
            case dropDecision = "drop_decision"
            case consoleLogs = "console"
            case resource
            case ndBuiltinCache = "nd_builtin_cache"
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.plugin = try container.decodeIfPresent(String.self, forKey: .plugin)
            self.service = try container.decodeIfPresent(String.self, forKey: .service) ?? ""
            self.partitionName = try container.decodeIfPresent(String.self, forKey: .partitionName)
            self.reporting =
                try container.decodeIfPresent(ReportingConfig.self, forKey: .reporting)
                ?? ReportingConfig()
            self.requestContext =
                try container.decodeIfPresent(
                    RequestContextConfig.self, forKey: .requestContext)
                ?? RequestContextConfig()
            self.maskDecision =
                try container.decodeIfPresent(String.self, forKey: .maskDecision)
                ?? defaultMaskDecisionPath
            self.dropDecision =
                try container.decodeIfPresent(String.self, forKey: .dropDecision)
                ?? defaultDropDecisionPath
            self.consoleLogs =
                try container.decodeIfPresent(Bool.self, forKey: .consoleLogs) ?? false
            self.resource = try container.decodeIfPresent(String.self, forKey: .resource)
            self.ndBuiltinCache = try container.decodeIfPresent(Bool.self, forKey: .ndBuiltinCache)
            try self.validate()
        }

        // MARK: - Validation

        /// Validates struct-local constraints. Does not require external
        /// context. The `ReportingConfig` validates its own invariants in
        /// its constructor; this method covers cross-field rules at the
        /// `DecisionLogsConfig` level.
        ///
        /// Ported from the struct-local portions of Go's
        /// `Config.validateAndInjectDefaults`.
        public func validate() throws {
            // ReportingConfig validates itself at construction time, so we
            // only need to check DecisionLogsConfig-level constraints here.

            // resource path must be a valid URL when explicitly provided and
            // no partition name overrides it
            if let name = partitionName, !name.isEmpty {
                // partition name will produce the resource in resolved()
            } else if let r = resource {
                guard URL(string: r) != nil else {
                    throw DecisionLogsConfigError.invalidResourcePath(
                        r, underlying: URLError(.badURL))
                }
            }
        }

        // MARK: - Validation with context

        /// Validates constraints that require context from the parent
        /// `Config` struct.
        ///
        /// Ported from the context-dependent portions of Go's
        /// `Config.validateAndInjectDefaults`.
        public func validateWithContext(
            serviceNames: [String],
            pluginNames: [String],
            trigger: TriggerMode?
        ) throws {
            // plugin validation
            if let pluginName = plugin {
                guard pluginNames.contains(pluginName) else {
                    throw DecisionLogsConfigError.invalidPluginName(pluginName)
                }
            }

            // service validation: when no plugin is set and a service name
            // is explicitly provided, verify it exists.
            if plugin == nil && !service.isEmpty {
                guard serviceNames.contains(service) else {
                    throw DecisionLogsConfigError.invalidServiceName(service)
                }
            }

            // trigger mode: the top-level override and per-plugin setting
            // must agree when both are specified.
            if let override = trigger, let configured = reporting.trigger,
                override != configured
            {
                throw DecisionLogsConfigError.invalidTriggerMode(
                    underlying: ConfigError(
                        code: .internalError,
                        message:
                            "trigger mode mismatch: top-level '\(override.rawValue)' "
                            + "vs decision_logs '\(configured.rawValue)'"
                    )
                )
            }
        }

        // MARK: - Resolution

        /// Returns a new config with all defaults injected and
        /// context-dependent properties resolved.
        ///
        /// Because some properties (service defaulting, trigger mode
        /// reconciliation, delay/size defaults) depend on top-level config
        /// state, they aren't applied at decode time. The parent config
        /// calls this method during its resolution phase to produce a
        /// fully-populated instance.
        ///
        /// NOTE on delay seconds: We keep the values in seconds
        /// here, matching the field name semantics. Consumers that need a
        /// `Duration` should convert via `Duration.seconds(...)`.
        ///
        /// Ported from Go's `Config.validateAndInjectDefaults`.
        public func resolved(
            services: [String],
            plugins: [String],
            trigger: TriggerMode?
        ) throws -> DecisionLogsConfig {
            // Resolve service: backwards-compatible default to first service
            // when no plugin is set, service is empty, services exist, and
            // console logging is disabled.
            let resolvedService: String
            if plugin == nil && service.isEmpty && !services.isEmpty && !consoleLogs {
                resolvedService = services[0]
            } else {
                resolvedService = service
            }

            // Resolve trigger mode: prefer top-level override, then
            // per-plugin value, then the global default.
            let resolvedTrigger = trigger ?? reporting.trigger ?? .default

            // Resolve delay defaults
            let resolvedMinDelay = reporting.minDelaySeconds ?? defaultMinDelaySeconds
            let resolvedMaxDelay = reporting.maxDelaySeconds ?? defaultMaxDelaySeconds

            // Resolve upload size limit (clamp to bounds)
            let requestedUploadLimit = reporting.uploadSizeLimitBytes ?? defaultUploadSizeLimitBytes
            let resolvedUploadLimit: Int64
            if requestedUploadLimit > maxUploadSizeLimitBytes {
                resolvedUploadLimit = maxUploadSizeLimitBytes
            } else if requestedUploadLimit < minUploadSizeLimitBytes {
                resolvedUploadLimit = minUploadSizeLimitBytes
            } else {
                resolvedUploadLimit = requestedUploadLimit
            }

            // Buffer-size fields are passed through unchanged. Their effective
            // defaults (`defaultBufferSizeLimitEvents`, `defaultBufferSizeLimitBytes`)
            // are applied at consumption time, keyed off the buffer type, so we do not
            // set them here. `nil` means "unlimited / use the default".

            let resolvedReporting = try ReportingConfig(
                bufferType: reporting.bufferType,
                bufferSizeLimitBytes: reporting.bufferSizeLimitBytes,
                bufferSizeLimitEvents: reporting.bufferSizeLimitEvents,
                uploadSizeLimitBytes: resolvedUploadLimit,
                minDelaySeconds: resolvedMinDelay,
                maxDelaySeconds: resolvedMaxDelay,
                maxDecisionsPerSecond: reporting.maxDecisionsPerSecond,
                trigger: resolvedTrigger
            )

            // Resolve resource path
            let resolvedResource: String?
            if let name = partitionName, !name.isEmpty {
                resolvedResource = "/logs/\(name)"
            } else {
                resolvedResource = resource ?? defaultResourcePath
            }

            return try DecisionLogsConfig(
                plugin: plugin,
                service: resolvedService,
                partitionName: partitionName,
                reporting: resolvedReporting,
                requestContext: requestContext,
                maskDecision: maskDecision,
                dropDecision: dropDecision,
                consoleLogs: consoleLogs,
                resource: resolvedResource,
                ndBuiltinCache: ndBuiltinCache
            )
        }
    }
}
