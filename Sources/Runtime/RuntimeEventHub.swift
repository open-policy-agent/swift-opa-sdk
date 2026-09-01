import Foundation
import Rego
import Synchronization

/// A multicast fan-out for ``OPA/RuntimeEvent`` values.
///
/// Each ``subscribe(bufferingPolicy:)`` call returns its own independent
/// `AsyncStream`, so every subscriber receives every yielded event.
/// A slow subscriber buffers according to its chosen policy and never
/// stalls the producer or the other subscribers.
///
/// Subscribers receive events from time-of-subscription forward. There is no
/// replay of prior events. The hub stays open for the owning Runtime's whole
/// lifetime (creation to `deinit`), so a subscription spans any number of
/// ``OPA/Runtime/run()`` sessions.
///
/// This mirrors the repo's `final class + Mutex` house style rather than using
/// an actor, so it can be yielded to from synchronous critical sections after
/// the caller's own lock has been released.
final class RuntimeEventHub: Sendable {
    private struct Storage {
        var subscribers: [UUID: AsyncStream<OPA.RuntimeEvent>.Continuation] = [:]
        var isFinished = false
    }

    private let storage = Mutex(Storage())

    /// Starts a new subscription. The returned stream receives every event
    /// yielded after this call, buffered per `bufferingPolicy`. Cancelling the
    /// consuming task (or breaking the `for await` loop) unsubscribes.
    ///
    /// If the hub has already finished, the returned stream is already
    /// finished, so the consumer's loop ends immediately.
    func subscribe(
        bufferingPolicy: AsyncStream<OPA.RuntimeEvent>.Continuation.BufferingPolicy = .unbounded
    ) -> AsyncStream<OPA.RuntimeEvent> {
        AsyncStream(bufferingPolicy: bufferingPolicy) { continuation in
            let id = UUID()
            let finished = storage.withLock { storage -> Bool in
                guard !storage.isFinished else { return true }
                storage.subscribers[id] = continuation
                return false
            }

            if finished {
                continuation.finish()
                return
            }

            continuation.onTermination = { [weak self] _ in
                self?.storage.withLock { _ = $0.subscribers.removeValue(forKey: id) }
            }
        }
    }

    /// Broadcasts an event to all current subscribers.
    func yield(_ event: OPA.RuntimeEvent) {
        // Snapshot continuations under the lock, then yield after releasing it.
        // The no-subscriber case (common) skips the snapshot entirely.
        let continuations = storage.withLock { storage -> [AsyncStream<OPA.RuntimeEvent>.Continuation] in
            guard !storage.isFinished, !storage.subscribers.isEmpty else { return [] }
            return Array(storage.subscribers.values)
        }
        for continuation in continuations {
            continuation.yield(event)
        }
    }

    /// Permanently finishes every subscription and rejects future ones, ending
    /// each subscriber's `for await` loop. Called once from the Runtime's
    /// `deinit`. Ending a subscriber's loop is the "event source is gone"
    /// signal.
    func finish() {
        let continuations = storage.withLock { storage -> [AsyncStream<OPA.RuntimeEvent>.Continuation] in
            guard !storage.isFinished else { return [] }
            storage.isFinished = true
            let values = Array(storage.subscribers.values)
            storage.subscribers.removeAll()
            return values
        }
        for continuation in continuations {
            continuation.finish()
        }
    }
}
