import AsyncHTTPClient
import Config
import Foundation
import Logging
import Rego
import Synchronization

extension OPA {
    /// The upload half of the service-backed decision logger: drains a
    /// ``DecisionLogBuffer`` and POSTs batches through a ``DecisionLogUploader``,
    /// retrying with exponential backoff.
    ///
    /// A pump has exactly one consumer — the task running ``run()`` — driven by
    /// two wake sources:
    ///
    /// - a randomized periodic timer bounded by `min_delay_seconds` /
    ///   `max_delay_seconds`, and
    /// - ``signal()``, called by producers after a successful enqueue, so
    ///   `event`-mode uploads happen promptly rather than waiting for a tick.
    ///
    /// Producer-side signalling is gated on an atomic flag so that a burst of
    /// enqueues costs one atomic exchange each instead of an `AsyncStream` yield
    /// each. Only the enqueue that finds no wake already pending pays for the
    /// yield.
    final class DecisionLogUploadPump: Sendable {
        /// Retry floor, matching OPA's `minRetryDelay`.
        private static var minRetrySeconds: Double { 0.1 }

        private let buffer: DecisionLogBuffer
        private let uploader: OPA.DecisionLogUploader?
        private let minDelaySeconds: Int64
        private let maxDelaySeconds: Int64
        private let logger: Logger

        /// `true` while a wake token is in flight and unconsumed.
        private let wakePending = Atomic<Bool>(false)
        private let wakeStream: AsyncStream<Void>
        private let wakeContinuation: AsyncStream<Void>.Continuation

        /// Seconds to wait after a failed upload. Doubles per consecutive
        /// failure, capped at `max_delay_seconds`, reset on success.
        private let backoffSeconds = Mutex<Double>(0)

        init(
            buffer: DecisionLogBuffer,
            uploader: OPA.DecisionLogUploader?,
            minDelaySeconds: Int64,
            maxDelaySeconds: Int64,
            logger: Logger
        ) {
            self.buffer = buffer
            self.uploader = uploader
            self.minDelaySeconds = minDelaySeconds
            self.maxDelaySeconds = maxDelaySeconds
            self.logger = logger
            (self.wakeStream, self.wakeContinuation) = AsyncStream.makeStream(
                bufferingPolicy: .bufferingNewest(1))
        }

        // MARK: - Producer side

        /// Nudges the consumer to drain. Cheap and idempotent: while a wake is
        /// already pending this is a single atomic exchange.
        func signal() {
            guard uploader != nil else { return }
            if !wakePending.exchange(true, ordering: .acquiringAndReleasing) {
                wakeContinuation.yield(())
            }
        }

        // MARK: - Consumer side

        /// Runs until the surrounding task is cancelled, then performs a
        /// best-effort final drain + upload.
        func run() async {
            // Nothing to upload against — park until cancelled so a caller's
            // `run()` task still has the lifetime it expects.
            guard uploader != nil else {
                while !Task.isCancelled {
                    do { try await Task.sleep(for: .seconds(3600)) } catch { break }
                }
                return
            }

            await withTaskGroup(of: Void.self) { group in
                // Periodic timer: signals a wake at randomized intervals. The
                // sleep is floored at `minRetrySeconds` so a 0/0 delay config
                // can't turn this into a busy-spin.
                group.addTask { [self] in
                    while !Task.isCancelled {
                        let delay = Swift.max(Self.minRetrySeconds, Double(self.randomDelaySeconds()))
                        do {
                            try await Task.sleep(for: .seconds(delay))
                        } catch {
                            break
                        }
                        self.signal()
                    }
                }

                // Drain loop. Cancellation ends the stream iteration.
                for await _ in wakeStream {
                    // Clear before draining: an event enqueued while we upload
                    // must be able to schedule another wake.
                    wakePending.store(false, ordering: .releasing)
                    await uploadOnce()
                }
                group.cancelAll()
            }

            await finalDrain()
        }

        // MARK: - Uploading

        /// Swaps the buffer out and uploads it. On failure hands the batch back
        /// and applies exponential backoff.
        private func uploadOnce() async {
            guard let uploader, !buffer.isEmpty else { return }
            let batch = buffer.takeBatch()
            let events = buffer.events(in: batch)
            guard !events.isEmpty else { return }

            do {
                try await uploader.upload(events)
                backoffSeconds.withLock { $0 = 0 }
            } catch {
                logger.warning("decision log upload failed, will retry: \(error)")
                buffer.restore(batch)
                let delay = backoffSeconds.withLock { backoff -> Double in
                    let next = backoff == 0 ? Self.minRetrySeconds : backoff * 2
                    // Floor at `minRetrySeconds` so a 0 (or sub-floor)
                    // max_delay_seconds can't drive a zero-delay retry storm.
                    backoff = max(Self.minRetrySeconds, min(next, Double(maxDelaySeconds)))
                    return backoff
                }
                do { try await Task.sleep(for: .seconds(delay)) } catch {}
            }
        }

        /// One last upload attempt at shutdown. The surrounding task is already
        /// cancelled by this point, so the upload runs detached with a fresh
        /// context.
        private func finalDrain() async {
            guard let uploader, !buffer.isEmpty else { return }
            let remaining = buffer.events(in: buffer.takeBatch())
            guard !remaining.isEmpty else { return }
            let logger = self.logger
            await Task.detached {
                do {
                    try await uploader.upload(remaining)
                } catch {
                    logger.warning("final decision log drain failed: \(error)")
                }
            }.value
        }

        private func randomDelaySeconds() -> Int64 {
            let lo = max(0, minDelaySeconds)
            let hi = max(lo, maxDelaySeconds)
            if lo == hi { return lo }
            return Int64.random(in: lo...hi)
        }
    }
}
