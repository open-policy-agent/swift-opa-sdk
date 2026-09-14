import Config
import DequeModule
import Foundation
import Logging
import Rego
import Synchronization

extension OPA {
    /// How a ``DecisionLogBuffer`` bounds itself, chosen at init time.
    ///
    /// These map to OPA's `buffer_type`:
    ///  - ``event(maxEvents:)`` is the "as-fast-as-possible" mode: a
    ///    count-bounded FIFO with O(1) enqueue, no per-event measurement and no
    ///    rate limiting.
    ///  - ``size(maxBytes:maxDecisionsPerSecond:)`` is the "bounded memory"
    ///    mode: the buffer holds at most `maxBytes` of serialized events
    ///    (0 = unlimited, the OPA default) and optionally rate-limits ingestion
    ///    via a token bucket.
    public enum BufferingPolicy: Sendable {
        case event(maxEvents: Int)
        case size(maxBytes: Int64, maxDecisionsPerSecond: Double?)
    }

    /// A single MPSC buffer of decision log events, bounded per its
    /// ``BufferingPolicy``. Backing storage is a `Deque`, so enqueue and
    /// oldest-eviction are O(1).
    ///
    /// This is the whole buffering core: one type covers both the `event` and
    /// `size` policies. `append(_:)` may be called concurrently from any number
    /// of tasks; `takeBatch()`/`restore(_:)` are only ever called from the
    /// owning ``DecisionLogUploadPump``. Nothing is logged while the lock is
    /// held, so a slow log handler can't stall producers.
    final class DecisionLogBuffer: Sendable {
        /// A buffered event plus its measured serialized size. Sizes travel with
        /// the batch so a retried upload never re-encodes to re-measure.
        struct StoredEvent: Sendable {
            let event: OPA.DecisionLogEvent
            let bytes: Int
        }

        typealias Batch = [StoredEvent]

        private struct State {
            var events: Deque<StoredEvent> = []
            var totalBytes: Int = 0
            var dropped: Int = 0
            /// Token bucket for `max_decisions_per_second` (size mode only).
            var tokens: Double
            var lastRefill: ContinuousClock.Instant
        }

        /// Why an ``append(_:)`` returned, reported outside the lock.
        private enum Outcome {
            case rateLimited
            case accepted(evicted: Int)
        }

        private let policy: BufferingPolicy
        private let logger: Logger
        private let state: Mutex<State>

        init(
            policy: BufferingPolicy,
            logger: Logger,
            startingEvents: [OPA.DecisionLogEvent] = []
        ) {
            self.policy = policy
            self.logger = logger
            // Token-bucket capacity is at least 1 so a sub-1 rate can still
            // accumulate a whole token over time (e.g. 0.5/sec => 1 event every
            // 2s). Capping at `rate` alone would strand rates < 1 below the
            // acceptance threshold and drop everything forever.
            let initialTokens: Double
            if case .size(_, let rate?) = policy { initialTokens = max(rate, 1) } else { initialTokens = 0 }
            self.state = Mutex(State(tokens: initialTokens, lastRefill: ContinuousClock().now))
            append(contentsOf: startingEvents)
        }

        /// Appends `event` unless the rate limiter rejects it (size mode), then
        /// evicts the oldest events until the buffer is back within its bound.
        /// Returns whether the event was accepted.
        @discardableResult
        func append(_ event: OPA.DecisionLogEvent) -> Bool {
            // Measurement and the clock read happen before the lock is taken.
            let bytes = measure(event)
            let now = ContinuousClock().now

            let outcome = state.withLock { state -> Outcome in
                if case .size(_, let rate?) = policy, rate > 0 {
                    refillTokens(&state, rate: rate, now: now)
                    if state.tokens < 1 {
                        state.dropped += 1
                        return .rateLimited
                    }
                    state.tokens -= 1
                }
                return .accepted(evicted: insert(StoredEvent(event: event, bytes: bytes), &state))
            }

            switch outcome {
            case .rateLimited:
                logger.debug("decision log event dropped: rate limit exceeded")
                return false
            case .accepted(let evicted):
                reportBufferDrops(evicted)
                return true
            }
        }

        /// Bulk append under a single lock acquisition, used to seed a
        /// replacement buffer at construction. Bypasses the rate limiter: these
        /// events were already admitted by the buffer being retired.
        func append(contentsOf events: [OPA.DecisionLogEvent]) {
            guard !events.isEmpty else { return }
            let sized = events.map { StoredEvent(event: $0, bytes: measure($0)) }
            let evicted = state.withLock { state -> Int in
                sized.reduce(0) { $0 + insert($1, &state) }
            }
            reportBufferDrops(evicted)
        }

        /// Removes and returns everything currently buffered. Hands the storage
        /// out and resets under the lock (O(1)), then builds the array outside
        /// it so a large drain never stalls producers.
        func takeBatch() -> Batch {
            let taken = state.withLock { state -> Deque<StoredEvent> in
                let events = state.events
                state.events = []
                state.totalBytes = 0
                return events
            }
            return Array(taken)
        }

        func events(in batch: Batch) -> [OPA.DecisionLogEvent] { batch.map(\.event) }

        /// Re-admits `batch` ahead of anything newer, dropping the newest events
        /// if that would exceed the bound.
        func restore(_ batch: Batch) {
            guard !batch.isEmpty else { return }
            let dropped = state.withLock { state -> Int in
                state.events.prepend(contentsOf: batch)
                state.totalBytes += batch.reduce(0) { $0 + $1.bytes }
                let dropped = evictFromNewest(&state)
                state.dropped += dropped
                return dropped
            }
            reportBufferDrops(dropped)
        }

        var isEmpty: Bool { state.withLock { $0.events.isEmpty } }
        var count: Int { state.withLock { $0.events.count } }
        var droppedCount: Int { state.withLock { $0.dropped } }
        var bufferedBytes: Int { state.withLock { $0.totalBytes } }

        // MARK: - Private

        /// Appends one measured event and evicts from the front (oldest) until
        /// the bound is satisfied. Returns how many events were evicted.
        ///
        /// In size mode at least one event is always kept, so an event larger
        /// than the whole limit still gets a chance to upload rather than being
        /// dropped on arrival.
        private func insert(_ sized: StoredEvent, _ state: inout State) -> Int {
            state.events.append(sized)
            state.totalBytes += sized.bytes

            var evicted = 0
            switch policy {
            case .event(let maxEvents):
                while state.events.count > max(1, maxEvents) {
                    state.totalBytes -= state.events.removeFirst().bytes
                    evicted += 1
                }
            case .size(let maxBytes, _):
                if maxBytes > 0 {
                    while state.totalBytes > Int(maxBytes), state.events.count > 1 {
                        state.totalBytes -= state.events.removeFirst().bytes
                        evicted += 1
                    }
                }
            }
            state.dropped += evicted
            return evicted
        }

        /// Evicts from the back (newest) until the bound is satisfied. Used by
        /// ``restore(_:)`` so a re-admitted batch wins over events that arrived
        /// while the upload was in flight.
        private func evictFromNewest(_ state: inout State) -> Int {
            var dropped = 0
            switch policy {
            case .event(let maxEvents):
                while state.events.count > max(1, maxEvents) {
                    state.totalBytes -= state.events.removeLast().bytes
                    dropped += 1
                }
            case .size(let maxBytes, _):
                if maxBytes > 0 {
                    while state.totalBytes > Int(maxBytes), state.events.count > 1 {
                        state.totalBytes -= state.events.removeLast().bytes
                        dropped += 1
                    }
                }
            }
            return dropped
        }

        /// Serialized size of `event`, or 0 when the policy doesn't measure
        /// (event mode, or an unlimited size buffer) so the number goes unused.
        private func measure(_ event: OPA.DecisionLogEvent) -> Int {
            guard case .size(let maxBytes, _) = policy, maxBytes > 0 else { return 0 }
            return (try? Self.sizeEncoder.encode(event).count) ?? 0
        }

        private func refillTokens(_ state: inout State, rate: Double, now: ContinuousClock.Instant) {
            let capacity = max(rate, 1)
            let elapsed = state.lastRefill.duration(to: now)
            let seconds =
                Double(elapsed.components.seconds)
                + Double(elapsed.components.attoseconds) / 1e18
            if seconds > 0 {
                state.tokens = min(capacity, state.tokens + seconds * rate)
                state.lastRefill = now
            }
        }

        /// Logs buffer-overflow drops. Never called inside `withLock`.
        private func reportBufferDrops(_ dropped: Int) {
            guard dropped > 0 else { return }
            let limitName: String
            if case .event = policy {
                limitName = "buffer_size_limit_events"
            } else {
                limitName = "buffer_size_limit_bytes"
            }
            logger.debug("dropped \(dropped) decision log event(s): \(limitName) exceeded")
        }

        /// Byte-measurement encoder, matching ``DecisionLogUploader``'s upload
        /// encoder so the measured size tracks the uploaded size.
        private static let sizeEncoder: JSONEncoder = {
            let e = JSONEncoder()
            e.dateEncodingStrategy = .iso8601
            e.outputFormatting = [.sortedKeys]
            return e
        }()
    }
}
