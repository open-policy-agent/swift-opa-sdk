import Foundation
import Rego

extension OPA {
    /// A discrete bundle or config fetch lifecycle event emitted by a
    /// ``OPA/Runtime``.
    ///
    /// Consume events via ``OPA/Runtime/events(bufferingPolicy:)``. Each event
    /// pairs a ``Source`` (which bundle, or the config provider) with a
    /// ``Kind`` describing what happened, plus the ``timestamp`` at which the
    /// Runtime observed it.
    ///
    /// Unlike polling the Runtime's snapshot accessors (``OPA/Runtime/bundles``,
    /// ``OPA/Runtime/activeConfig``), the event stream delivers *every* discrete
    /// transition, so a consumer that keeps up never misses an intermediate
    /// swap between two fetches.
    ///
    /// ## Ordering
    ///
    /// Fetch events for a single ``Source`` arrive in order (each source is
    /// polled by a sequential loop that pairs a ``Kind/fetchStarted`` with
    /// exactly one terminal kind). There is no global ordering *across* sources,
    /// since bundle loaders poll concurrently. If an ordering is necessary,
    /// consider using the ``timestamp`` field.
    ///
    /// The ``Source/runtime`` source brackets a ``OPA/Runtime/run()`` session
    /// with a ``Kind/runStarted`` before any worker events and a
    /// ``Kind/runStopped`` after they have all stopped, rather than pairing
    /// fetch attempts.
    public struct RuntimeEvent: Sendable {
        /// What the event is about: a specific configured bundle, the config
        /// provider, or the Runtime itself.
        public enum Source: Sendable, Hashable, CustomStringConvertible {
            /// A configured bundle resource, identified by its name.
            case bundle(name: String)
            /// The config provider (e.g. discovery).
            case config
            /// The Runtime itself (run-loop lifecycle events).
            case runtime

            public var description: String {
                switch self {
                case .bundle(let name): return "bundle:\(name)"
                case .config: return "config"
                case .runtime: return "runtime"
                }
            }
        }

        /// What the event represents. This is currently limited to fetch
        /// outcomes and run-loop lifecycle transitions, but the list may grow
        /// to event types beyond these.
        public enum Kind: Sendable {
            /// A fetch attempt is about to begin.
            case fetchStarted
            /// The source responded, but the content was unchanged.
            case notModified
            /// New content was loaded and applied. `revision` is the bundle
            /// manifest revision (`nil` for the config source, which has no
            /// manifest, or when the bundle manifest carries no revision).
            case updated(revision: String?)
            /// The fetch attempt failed. `code` is the category label (usable
            /// as a metrics label). `httpStatus` carries the HTTP status when
            /// the failure occurred after a response (`nil` for transport
            /// failures and non-HTTP sources).
            case failed(code: RuntimeError.Code, httpStatus: Int?)
            /// A ``OPA/Runtime/run()`` session has begun. Emitted once with
            /// ``Source/runtime`` before any worker events.
            case runStarted
            /// A ``OPA/Runtime/run()`` session has ended (normal return, thrown
            /// error, or cancellation). Emitted once with ``Source/runtime``
            /// after all workers have stopped.
            case runStopped
        }

        /// The bundle or config source this event is about.
        public let source: Source
        /// What the event represents.
        public let kind: Kind
        /// When the Runtime observed the event.
        public let timestamp: Date

        public init(source: Source, kind: Kind, timestamp: Date = Date()) {
            self.source = source
            self.kind = kind
            self.timestamp = timestamp
        }
    }
}
