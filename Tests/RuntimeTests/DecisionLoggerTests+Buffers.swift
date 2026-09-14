import AST
import Config
import Foundation
import Logging
import Rego
import Testing

@testable import Runtime

// MARK: - Event policy (count-bounded)

@Suite("DecisionLogBuffer (event policy)")
struct DecisionLogBufferEventTests {
    private func makeBuffer(
        maxEvents: Int, startingEvents: [OPA.DecisionLogEvent] = []
    ) -> OPA.DecisionLogBuffer {
        OPA.DecisionLogBuffer(
            policy: .event(maxEvents: maxEvents),
            logger: Logger(label: "test.eventbuffer"),
            startingEvents: startingEvents)
    }

    private func ids(_ buffer: OPA.DecisionLogBuffer) -> [String] {
        buffer.events(in: buffer.takeBatch()).map(\.decisionID)
    }

    @Test("appends in FIFO order and drains empty")
    func testFIFO() {
        let buffer = makeBuffer(maxEvents: 8)
        for i in 0..<4 { buffer.append(makeTestEvent("e\(i)")) }

        #expect(buffer.count == 4)
        #expect(!buffer.isEmpty)
        #expect(ids(buffer) == ["e0", "e1", "e2", "e3"])
        #expect(buffer.isEmpty)
        #expect(buffer.count == 0)
        #expect(buffer.takeBatch().isEmpty)
    }

    @Test("evicts the oldest event once at the limit")
    func testOverflowDropsOldest() {
        let buffer = makeBuffer(maxEvents: 3)
        for i in 0..<10 { buffer.append(makeTestEvent("e\(i)")) }

        #expect(buffer.count == 3)
        #expect(buffer.droppedCount == 7)
        #expect(ids(buffer) == ["e7", "e8", "e9"])
    }

    @Test("seeding applies the limit, keeping the newest events")
    func testSeeding() {
        let seed = (0..<5).map { makeTestEvent("s\($0)") }
        let buffer = makeBuffer(maxEvents: 3, startingEvents: seed)

        #expect(buffer.count == 3)
        #expect(buffer.droppedCount == 2)
        #expect(ids(buffer) == ["s2", "s3", "s4"])
    }

    @Test("restore re-admits a failed batch ahead of newer events")
    func testRestoreOrdering() {
        let buffer = makeBuffer(maxEvents: 8)
        for i in 0..<3 { buffer.append(makeTestEvent("old\(i)")) }
        let batch = buffer.takeBatch()

        // Newer events arrive while the upload is in flight.
        buffer.append(makeTestEvent("new0"))
        buffer.restore(batch)

        #expect(buffer.droppedCount == 0)
        #expect(ids(buffer) == ["old0", "old1", "old2", "new0"])
    }

    @Test("restore drops the newest events when the batch doesn't fit")
    func testRestoreOverflowDropsNewest() {
        let buffer = makeBuffer(maxEvents: 3)
        for i in 0..<3 { buffer.append(makeTestEvent("old\(i)")) }
        let batch = buffer.takeBatch()
        for i in 0..<3 { buffer.append(makeTestEvent("new\(i)")) }

        buffer.restore(batch)

        // The retried batch wins. the events that arrived since are dropped.
        #expect(buffer.count == 3)
        #expect(buffer.droppedCount == 3)
        #expect(ids(buffer) == ["old0", "old1", "old2"])
    }

    @Test("sustained overflow stays fast", .timeLimit(.minutes(1)))
    func testSustainedOverflowThroughput() {
        // With an Array-backed buffer this is O(n^2): 200k appends each
        // memmoving a full 10k-event buffer. A Deque keeps it O(1) per append.
        let buffer = makeBuffer(maxEvents: 10_000)
        for i in 0..<200_000 { buffer.append(makeTestEvent("e\(i)")) }

        #expect(buffer.count == 10_000)
        #expect(buffer.droppedCount == 190_000)
    }

    @Test("concurrent producers all land in the buffer")
    func testConcurrentProducers() async {
        let producers = 8
        let perProducer = 500
        let buffer = makeBuffer(maxEvents: producers * perProducer)

        await withTaskGroup(of: Void.self) { group in
            for p in 0..<producers {
                group.addTask {
                    for i in 0..<perProducer {
                        buffer.append(makeTestEvent("p\(p)-\(i)"))
                    }
                }
            }
        }

        #expect(buffer.count == producers * perProducer)
        #expect(buffer.droppedCount == 0)

        // Every producer's events keep their relative order.
        let drained = ids(buffer)
        for p in 0..<producers {
            let mine = drained.filter { $0.hasPrefix("p\(p)-") }
            #expect(mine == (0..<perProducer).map { "p\(p)-\($0)" })
        }
    }
}

// MARK: - Size policy (byte-bounded)

@Suite("DecisionLogBuffer (size policy)")
struct DecisionLogBufferSizeTests {
    private func makeBuffer(
        maxBytes: Int64, ratePerSecond: Double? = nil,
        startingEvents: [OPA.DecisionLogEvent] = []
    ) -> OPA.DecisionLogBuffer {
        OPA.DecisionLogBuffer(
            policy: .size(maxBytes: maxBytes, maxDecisionsPerSecond: ratePerSecond),
            logger: Logger(label: "test.sizebuffer"), startingEvents: startingEvents)
    }

    private func ids(_ buffer: OPA.DecisionLogBuffer) -> [String] {
        buffer.events(in: buffer.takeBatch()).map(\.decisionID)
    }

    /// Measured size of a single test event, per the buffer's own accounting.
    /// Note that this varies with the decision ID's length, so tests that size a
    /// limit in multiples of it should probe with an equal-width ID.
    private func eventSize(_ event: OPA.DecisionLogEvent) -> Int {
        let probe = makeBuffer(maxBytes: 1 << 30)
        probe.append(event)
        return probe.bufferedBytes
    }

    @Test("unlimited buffer never measures or evicts")
    func testUnlimited() {
        let buffer = makeBuffer(maxBytes: 0)
        for i in 0..<100 { buffer.append(makeTestEvent("u\(i)")) }

        #expect(buffer.count == 100)
        #expect(buffer.droppedCount == 0)
        // Nothing is serialized when the limit is unlimited, so there is no
        // byte total to report.
        #expect(buffer.bufferedBytes == 0)
    }

    @Test("evicts oldest events to stay within buffer_size_limit_bytes")
    func testByteLimitEvictsOldest() {
        let unit = eventSize(makeTestEvent("x0"))
        #expect(unit > 0)

        // Room for three events, but not four.
        let buffer = makeBuffer(maxBytes: Int64(unit * 3))
        for i in 0..<10 { buffer.append(makeTestEvent("b\(i)")) }

        #expect(buffer.count == 3)
        #expect(buffer.droppedCount == 7)
        #expect(buffer.bufferedBytes <= unit * 3)
        #expect(ids(buffer) == ["b7", "b8", "b9"])
    }

    @Test("an event larger than the whole limit is still buffered")
    func testOversizedEventKept() {
        let buffer = makeBuffer(maxBytes: 1)
        buffer.append(makeTestEvent("big"))

        #expect(buffer.count == 1)
        #expect(buffer.droppedCount == 0)
    }

    @Test("takeBatch resets the byte total, restore restores it")
    func testByteAccountingRoundTrip() {
        let unit = eventSize(makeTestEvent("x0"))
        let buffer = makeBuffer(maxBytes: Int64(unit * 10))
        for i in 0..<3 { buffer.append(makeTestEvent("r\(i)")) }
        let before = buffer.bufferedBytes

        let batch = buffer.takeBatch()
        #expect(buffer.bufferedBytes == 0)

        buffer.restore(batch)
        #expect(buffer.bufferedBytes == before)
        #expect(buffer.count == 3)
        #expect(ids(buffer) == ["r0", "r1", "r2"])
    }

    @Test("restore re-admits ahead of newer events and drops the newest on overflow")
    func testRestoreOverflow() {
        // Probe with an equal-width decision ID so three events fit exactly.
        let unit = eventSize(makeTestEvent("old0"))
        let buffer = makeBuffer(maxBytes: Int64(unit * 3))
        for i in 0..<3 { buffer.append(makeTestEvent("old\(i)")) }
        let batch = buffer.takeBatch()
        for i in 0..<3 { buffer.append(makeTestEvent("new\(i)")) }

        buffer.restore(batch)

        #expect(buffer.count == 3)
        #expect(ids(buffer) == ["old0", "old1", "old2"])
    }

    @Test("seeding bypasses the rate limiter")
    func testSeedingBypassesRateLimit() {
        // A rate of 1/sec would reject all but the first event on ingest, but
        // seeded events were already admitted by the retired logger.
        let seed = (0..<5).map { makeTestEvent("s\($0)") }
        let buffer = makeBuffer(maxBytes: 0, ratePerSecond: 1, startingEvents: seed)

        #expect(buffer.count == 5)
        #expect(buffer.droppedCount == 0)
    }

    @Test("rate limiting rejects events beyond the token bucket")
    func testRateLimit() {
        let buffer = makeBuffer(maxBytes: 0, ratePerSecond: 2)
        var accepted = 0
        for i in 0..<10 {
            if buffer.append(makeTestEvent("r\(i)")) { accepted += 1 }
        }

        #expect(accepted <= 2)
        #expect(buffer.count == accepted)
        #expect(buffer.droppedCount == 10 - accepted)
    }

    @Test("a sub-1 rate still admits events rather than dropping everything")
    func testFractionalRateAdmits() {
        // Token-bucket capacity is max(rate, 1), so a rate below 1 can still
        // accumulate a whole token. Capping capacity at `rate` (0.5) would keep
        // tokens under the acceptance threshold and drop every event forever.
        let buffer = makeBuffer(maxBytes: 0, ratePerSecond: 0.5)
        #expect(buffer.append(makeTestEvent("r0")))
        #expect(buffer.count == 1)
        #expect(buffer.droppedCount == 0)
    }
}
