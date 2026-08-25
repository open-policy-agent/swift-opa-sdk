import Foundation

/// The shared surface of structured OPA runtime errors: a category
/// ``code``, a human-readable ``message``, and an optional underlying ``cause``.
///
/// Both ``RuntimeError`` and ``BundleFetchError`` conform to this protocol, so
/// a handler can match `any RuntimeFailure` to treat them uniformly without
/// knowing the concrete type. This setup means simple codes can be used for
/// metrics labels, while still allowing logging of detailed error messages.
public protocol RuntimeFailure: Swift.Error, Sendable {
    /// A code representing the high-level domain of the error.
    var code: RuntimeError.Code { get }

    /// A message providing additional context about the error.
    var message: String { get }

    /// The original error which led to this error being thrown.
    var cause: (any Swift.Error)? { get }
}

/// A representation of an error thrown by the OPA Runtime.
///
/// A RuntimeError will have a ``code`` specifying the type of error.
/// See ``RuntimeError/Code`` for available codes.
public struct RuntimeError: RuntimeFailure {

    /// A domain-specific code describing the type of error.
    public struct Code: Hashable, Sendable {
        internal enum InternalCode {
            case internalError

            // Bundle errors
            case bundleInitializationError
            case bundleLoadError
            case bundleTransportError
            case bundleNameConflictError
            case bundleRootConflictError
            case bundleUnpreparedError
            case invalidArgumentError

            // Discovery errors
            case discoveryNotSupported
        }

        private let internalCode: InternalCode

        internal init(_ code: InternalCode) {
            self.internalCode = code
        }

        // Bundle-related codes
        public static let bundleInitializationError = Code(.bundleInitializationError)
        public static let bundleLoadError = Code(.bundleLoadError)
        /// A bundle fetch that could not complete or be read (network, DNS, TLS,
        /// or disk I/O), before any source response was available.
        public static let bundleTransportError = Code(.bundleTransportError)
        public static let bundleNameConflictError = Code(.bundleNameConflictError)
        public static let bundleRootConflictError = Code(.bundleRootConflictError)
        public static let bundleUnpreparedError = Code(.bundleUnpreparedError)
        public static let internalError = Code(.internalError)
        public static let invalidArgumentError = Code(.invalidArgumentError)

        // Discovery-related codes
        public static let discoveryNotSupported = Code(.discoveryNotSupported)
    }

    /// A code representing the high-level domain of the error.
    public var code: Code

    /// A message providing additional context about the error.
    public var message: String

    /// The original error which led to this error being thrown.
    public var cause: (any Swift.Error)?

    public init(code: Code, message: String, cause: (any Swift.Error)? = nil) {
        self.code = code
        self.message = message
        self.cause = cause
    }
}

extension RuntimeError.Code: CustomStringConvertible {
    /// A short string representation of each error code.
    public var description: String {
        switch self.internalCode {
        case .internalError: return "internalError"
        case .bundleInitializationError: return "bundleInitializationError"
        case .bundleLoadError: return "bundleLoadError"
        case .bundleTransportError: return "bundleTransportError"
        case .bundleNameConflictError: return "bundleNameConflictError"
        case .bundleRootConflictError: return "bundleRootConflictError"
        case .bundleUnpreparedError: return "bundleUnpreparedError"
        case .invalidArgumentError: return "invalidArgumentError"
        case .discoveryNotSupported: return "discoveryNotSupported"
        }
    }
}

/// An error for a failed bundle or discovery fetch.
///
/// ``code`` is a simple category label and works for both disk and HTTP bundle
/// sources. ``httpStatus`` and ``host`` carry HTTP-only information about the error.
/// They are `nil` for non-HTTP (disk) sources, and ``httpStatus`` is also `nil`
/// for transport failures that occur before any HTTP response arrives.
///
/// Consumers can label metrics off these fields directly rather than parsing
/// the detailed ``message`` field.
public struct BundleFetchError: RuntimeFailure {
    /// A code representing the high-level domain of the error.
    public var code: RuntimeError.Code

    /// A message providing additional context about the error.
    public var message: String

    /// The original error which led to this error being thrown.
    public var cause: (any Swift.Error)?

    /// The HTTP status code returned by the server, when the failure occurred
    /// after a response was received. `nil` for transport failures and for
    /// non-HTTP (disk) sources.
    public var httpStatus: Int?

    /// The host the failing request targeted, when known. `nil` for non-HTTP
    /// (disk) sources.
    public var host: String?

    public init(
        code: RuntimeError.Code,
        message: String,
        cause: (any Swift.Error)? = nil,
        httpStatus: Int? = nil,
        host: String? = nil
    ) {
        self.code = code
        self.message = message
        self.cause = cause
        self.httpStatus = httpStatus
        self.host = host
    }
}

extension BundleFetchError {
    /// Builds a transport-layer failure (network, DNS, TLS) that occurred
    /// before any HTTP response was available. Leaves ``httpStatus`` nil and
    /// derives ``host`` from the request URL so callers can still label by host.
    static func transport(url: URL, cause: any Swift.Error) -> BundleFetchError {
        BundleFetchError(
            code: .bundleTransportError,
            message: "Bundle download on url \(url) failed: \(cause)",
            cause: cause,
            host: url.host
        )
    }
}
