import AST
import Config
import Foundation
import Logging
import NIOConcurrencyHelpers
import Rego
import Testing

@testable import Runtime

// MARK: - Shared helpers

/// Builds a decision log event for tests.
func makeTestEvent(
    _ id: String,
    input: AST.RegoValue = ["x": 1],
    result: AST.RegoValue = ["allowed": true]
) -> OPA.DecisionLogEvent {
    OPA.DecisionLogEvent(
        decisionID: id, input: input, result: result, timestamp: Date(timeIntervalSince1970: 0))
}

func makeServiceConfig(url: String) throws -> OPA.ServiceConfig {
    try OPA.ServiceConfig(url: URL(string: url)!)
}

func makeDecisionLogsConfig(
    service: String = "svc",
    bufferType: String = eventBufferType,
    bufferSizeLimitBytes: Int64? = nil,
    bufferSizeLimitEvents: Int64? = nil,
    uploadSizeLimitBytes: Int64? = nil,
    maxDecisionsPerSecond: Double? = nil,
    consoleLogs: Bool = false
) throws -> OPA.DecisionLogsConfig {
    let reporting = try OPA.ReportingConfig(
        bufferType: bufferType,
        bufferSizeLimitBytes: bufferSizeLimitBytes,
        bufferSizeLimitEvents: bufferSizeLimitEvents,
        uploadSizeLimitBytes: uploadSizeLimitBytes,
        minDelaySeconds: 1,
        maxDelaySeconds: 1,
        maxDecisionsPerSecond: maxDecisionsPerSecond)
    return try OPA.DecisionLogsConfig(
        service: service, reporting: reporting, consoleLogs: consoleLogs, resource: defaultResourcePath)
}

// MARK: - Standalone logger tests

@Suite("DecisionLogger standalone")
struct DecisionLoggerStandaloneTests {
    @Test("event-mode logger uploads enqueued events (no Runtime)")
    func testEventLoggerUploads() async throws {
        let server = try await TestLogIngestServer.start()
        defer { Task { try? await server.shutdown() } }

        let service = try makeServiceConfig(url: server.baseURL)
        let dl = try makeDecisionLogsConfig(bufferType: eventBufferType)
        let logger = try OPA.BufferedDecisionLogger(
            config: dl, service: service, httpClientConfig: nil, httpClientCache: nil,
            logger: Logger(label: "test.eventlogger"), startingEvents: [])

        let runTask = Task { await logger.run() }
        defer { runTask.cancel() }

        await logger.log(makeTestEvent("d1"))
        await logger.log(makeTestEvent("d2"))

        let ok = await waitUntil { server.events.count >= 2 }
        #expect(ok, "expected 2 events, got \(server.events.count)")
        #expect(Set(server.events.map(\.decisionID)) == ["d1", "d2"])

        // Uploads should be gzip-encoded JSON.
        #expect(server.requests.allSatisfy { $0.headerValue(for: "content-encoding") == "gzip" })
        #expect(server.requests.allSatisfy { $0.method == "POST" })
    }

    @Test("size-mode logger uploads enqueued events (no Runtime)")
    func testSizeLoggerUploads() async throws {
        let server = try await TestLogIngestServer.start()
        defer { Task { try? await server.shutdown() } }

        let service = try makeServiceConfig(url: server.baseURL)
        let dl = try makeDecisionLogsConfig(bufferType: sizeBufferType)
        let logger = try OPA.BufferedDecisionLogger(
            config: dl, service: service, httpClientConfig: nil, httpClientCache: nil,
            logger: Logger(label: "test.sizelogger"), startingEvents: [])

        let runTask = Task { await logger.run() }
        defer { runTask.cancel() }

        await logger.log(makeTestEvent("s1"))
        let ok = await waitUntil { server.events.contains { $0.decisionID == "s1" } }
        #expect(ok)
    }

    @Test("event-mode buffer drops oldest beyond buffer_size_limit_events")
    func testEventBufferOverflow() async throws {
        // No service -> no uploads; buffer just accumulates and evicts.
        let dl = try makeDecisionLogsConfig(bufferSizeLimitEvents: 3)
        let logger = try OPA.BufferedDecisionLogger(
            config: dl, service: nil, httpClientConfig: nil, httpClientCache: nil,
            logger: Logger(label: "test.overflow"), startingEvents: [])

        for i in 0..<10 {
            await logger.log(makeTestEvent("e\(i)"))
        }
        #expect(logger.bufferedCount == 3)
        #expect(logger.droppedCount == 7)

        // The three most-recent events survive.
        let remaining = await logger.drain().map(\.decisionID)
        #expect(remaining == ["e7", "e8", "e9"])
    }

    @Test("drained events seed a replacement logger")
    func testDrainAndSeed() async throws {
        let dl = try makeDecisionLogsConfig()
        let first = try OPA.BufferedDecisionLogger(
            config: dl, service: nil, httpClientConfig: nil, httpClientCache: nil,
            logger: Logger(label: "test.seed1"), startingEvents: [])
        await first.log(makeTestEvent("a"))
        await first.log(makeTestEvent("b"))

        let drained = await first.drain()
        #expect(drained.count == 2)

        let second = try OPA.BufferedDecisionLogger(
            config: dl, service: nil, httpClientConfig: nil, httpClientCache: nil,
            logger: Logger(label: "test.seed2"), startingEvents: drained)
        #expect(second.bufferedCount == 2)
    }
}

// MARK: - Rate limiting

@Suite("DecisionLogger rate limiting")
struct DecisionLoggerRateLimitTests {
    @Test("max_decisions_per_second drops events beyond the rate")
    func testRateLimit() async throws {
        // Rate of 2/sec, no service. A tight burst of 10 should mostly drop.
        let dl = try makeDecisionLogsConfig(
            bufferType: sizeBufferType, maxDecisionsPerSecond: 2)
        let logger = try OPA.BufferedDecisionLogger(
            config: dl, service: nil, httpClientConfig: nil, httpClientCache: nil,
            logger: Logger(label: "test.rate"), startingEvents: [])

        for i in 0..<10 {
            await logger.log(makeTestEvent("r\(i)"))
        }
        // Token bucket starts full at `rate` (2), so at most ~2 are accepted
        // in an instantaneous burst; the rest are dropped.
        #expect(logger.bufferedCount <= 2)
        #expect(logger.droppedCount >= 8)
    }
}

// MARK: - Upload chunking

@Suite("DecisionLogUploader chunking")
struct DecisionLogUploaderTests {
    @Test("encodeChunks splits batches exceeding the upload size limit")
    func testChunking() throws {
        let service = try makeServiceConfig(url: "http://127.0.0.1:9/logs")
        let events = (0..<5).map { makeTestEvent("c\($0)") }

        // Size a single event's compressed payload, then set the limit to just
        // fit one event so a multi-event batch must split.
        let sizer = try OPA.DecisionLogUploader(
            service: service, serviceName: "test-service", resource: "/logs",
            uploadSizeLimitBytes: maxUploadSizeLimitBytes,
            httpClientConfig: nil, httpClientCache: nil, logger: Logger(label: "test.sizer"))
        let singleSize = try sizer.encodeChunks([events[0]])[0].count

        let uploader = try OPA.DecisionLogUploader(
            service: service, serviceName: "test-service", resource: "/logs",
            uploadSizeLimitBytes: Int64(singleSize),
            httpClientConfig: nil, httpClientCache: nil, logger: Logger(label: "test.chunk"))
        let chunks = try uploader.encodeChunks(events)

        // Each event alone fills a chunk; nothing should be dropped.
        #expect(chunks.count == 5)
        #expect(chunks.allSatisfy { $0.count <= singleSize })
    }

    @Test("encodeChunks keeps a whole batch in one chunk when it fits")
    func testSingleChunk() throws {
        let service = try makeServiceConfig(url: "http://127.0.0.1:9/logs")
        let uploader = try OPA.DecisionLogUploader(
            service: service, serviceName: "test-service", resource: "/logs",
            uploadSizeLimitBytes: defaultUploadSizeLimitBytes,
            httpClientConfig: nil, httpClientCache: nil, logger: Logger(label: "test.chunk2"))
        let events = (0..<5).map { makeTestEvent("c\($0)") }
        let chunks = try uploader.encodeChunks(events)
        #expect(chunks.count == 1)
    }
}

// MARK: - Console

@Suite("ConsoleDecisionLogger")
struct ConsoleDecisionLoggerTests {
    @Test("emit writes the event as a JSON line")
    func testEmit() {
        let capture = CapturingLogHandler()
        let logger = Logger(label: "test.console") { _ in capture }
        OPA.ConsoleDecisionLogger.emit(makeTestEvent("con1"), using: logger)

        let lines = capture.messages(atLeast: .info)
        #expect(lines.count == 1)
        #expect(lines[0].contains("\"decision_id\":\"con1\""))
        #expect(lines[0].contains("\"allowed\":true"))
    }
}
