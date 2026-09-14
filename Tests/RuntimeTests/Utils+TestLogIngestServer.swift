import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import Rego
import Runtime
import SWCompression

// MARK: - Decision Log Ingest Test Server

/// A minimal HTTP server that accepts decision-log uploads (`POST`), gunzips
/// and decodes the JSON event array, and records both the raw request metadata
/// and the decoded events for assertions.
///
/// Modeled on `TestBundleServer`, but captures request bodies (which the bundle
/// server does not need to do).
final class TestLogIngestServer: @unchecked Sendable {
    let port: Int
    let baseURL: String

    private let channel: Channel
    private let group: EventLoopGroup
    private let store: IngestStore

    private init(channel: Channel, group: EventLoopGroup, store: IngestStore) {
        self.channel = channel
        self.group = group
        self.store = store
        self.port = channel.localAddress!.port!
        self.baseURL = "http://127.0.0.1:\(self.port)"
    }

    /// All decoded events received so far, across all uploads, in order.
    var events: [OPA.DecisionLogEvent] { store.events }

    /// Number of upload requests received.
    var uploadCount: Int { store.uploadCount }

    /// Captured request metadata (method, uri, headers) per upload.
    var requests: [IngestRequest] { store.requests }

    /// Forces the server to respond with this status code (e.g. 500) to test
    /// retry/backoff. `nil` (default) responds 200.
    func setForcedStatus(_ code: UInt?) { store.forcedStatus = code }

    static func start() async throws -> TestLogIngestServer {
        TestLogging.ensureBootstrapped()
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let store = IngestStore()

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(IngestHandler(store: store))
                }
            }

        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        return TestLogIngestServer(channel: channel, group: group, store: store)
    }

    func shutdown() async throws {
        try await channel.close()
        try await group.shutdownGracefully()
    }
}

struct IngestRequest: Sendable {
    let method: String
    let uri: String
    let headers: [(name: String, value: String)]

    func headerValue(for name: String) -> String? {
        headers.first(where: { $0.name.lowercased() == name.lowercased() })?.value
    }
}

/// Thread-safe capture of received uploads.
final class IngestStore: @unchecked Sendable {
    private let lock = NSLock()
    private var _events: [OPA.DecisionLogEvent] = []
    private var _requests: [IngestRequest] = []
    private var _uploadCount = 0
    private var _forcedStatus: UInt?

    var events: [OPA.DecisionLogEvent] { lock.withLock { _events } }
    var requests: [IngestRequest] { lock.withLock { _requests } }
    var uploadCount: Int { lock.withLock { _uploadCount } }
    var forcedStatus: UInt? {
        get { lock.withLock { _forcedStatus } }
        set { lock.withLock { _forcedStatus = newValue } }
    }

    private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    /// Records an upload. Gunzips the body when `content-encoding: gzip`, then
    /// decodes the JSON event array.
    func record(request: IngestRequest, body: Data) {
        let jsonData: Data
        if request.headerValue(for: "content-encoding")?.lowercased() == "gzip", !body.isEmpty {
            jsonData = (try? GzipArchive.unarchive(archive: body)) ?? body
        } else {
            jsonData = body
        }
        let decoded = (try? Self.decoder.decode([OPA.DecisionLogEvent].self, from: jsonData)) ?? []
        lock.withLock {
            _uploadCount += 1
            _requests.append(request)
            _events.append(contentsOf: decoded)
        }
    }
}

private final class IngestHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let store: IngestStore
    private var requestHead: HTTPRequestHead?
    private var bodyBuffer: ByteBuffer?

    init(store: IngestStore) {
        self.store = store
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)
        switch part {
        case .head(let head):
            requestHead = head
            bodyBuffer = context.channel.allocator.buffer(capacity: 0)
        case .body(var chunk):
            bodyBuffer?.writeBuffer(&chunk)
        case .end:
            guard let head = requestHead else { return }
            let headers = head.headers.map { (name: $0.name, value: $0.value) }
            let bytes = bodyBuffer.map { Data($0.readableBytesView) } ?? Data()
            store.record(
                request: IngestRequest(method: head.method.rawValue, uri: head.uri, headers: headers),
                body: bytes)

            let status = store.forcedStatus.map { HTTPResponseStatus(statusCode: Int($0)) } ?? .ok
            var responseHead = HTTPResponseHead(version: head.version, status: status)
            responseHead.headers.add(name: "content-length", value: "0")
            context.write(wrapOutboundOut(.head(responseHead)), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)

            requestHead = nil
            bodyBuffer = nil
        }
    }
}
