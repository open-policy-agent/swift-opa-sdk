import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

// MARK: - ETag Test Server Infrastructure

/// Captures an incoming HTTP request's key details for later inspection.
struct ReceivedRequest: Sendable {
    let method: String
    let uri: String
    let headers: [(name: String, value: String)]

    func headerValue(for name: String) -> String? {
        headers.first(where: { $0.name.lowercased() == name.lowercased() })?.value
    }

    func allHeaderValues(for name: String) -> [String] {
        headers.filter { $0.name.lowercased() == name.lowercased() }.map(\.value)
    }
}

// MARK: - Per-Path State

/// Per-path response state. Each registered URI has its own `PathState`.
/// For the single-path convenience API, one `PathState` is registered under
/// a wildcard key and reused for every request.
final class PathState: @unchecked Sendable {
    private let lock = NSLock()

    private var _data: Data
    private var _etag: String?
    private var _forceStatusCode: UInt?
    private var _contentType: String
    /// If non-nil, the server will delay this long before responding,
    /// simulating long-polling behavior.
    private var _longPollDelay: Duration?

    init(
        data: Data,
        etag: String?,
        forceStatusCode: UInt? = nil,
        contentType: String = "application/gzip",
        longPollDelay: Duration? = nil
    ) {
        self._data = data
        self._etag = etag
        self._forceStatusCode = forceStatusCode
        self._contentType = contentType
        self._longPollDelay = longPollDelay
    }

    var data: Data {
        get { lock.withLock { _data } }
        set { lock.withLock { _data = newValue } }
    }
    var etag: String? {
        get { lock.withLock { _etag } }
        set { lock.withLock { _etag = newValue } }
    }
    var forceStatusCode: UInt? {
        get { lock.withLock { _forceStatusCode } }
        set { lock.withLock { _forceStatusCode = newValue } }
    }
    var contentType: String {
        get { lock.withLock { _contentType } }
        set { lock.withLock { _contentType = newValue } }
    }
    var longPollDelay: Duration? {
        get { lock.withLock { _longPollDelay } }
        set { lock.withLock { _longPollDelay = newValue } }
    }
}

// MARK: - Server State

/// Thread-safe collection of per-path states plus a running request log.
///
/// Supports two modes:
///  - **Multi-path**: paths registered explicitly, looked up by URI.
///  - **Single-path**: one `PathState` stored under a sentinel wildcard key
///    and returned for every URI. This preserves the original
///    `ETagBundleServer` ergonomics (`server.state.bundleData`, etc.).
final class ServerState: @unchecked Sendable {
    /// Sentinel key used for single-path (wildcard) registration.
    fileprivate static let wildcardKey = "*"

    private let lock = NSLock()
    private var _paths: [String: PathState]
    private var _requests: [ReceivedRequest] = []
    private let _isSinglePath: Bool

    /// Multi-path initializer.
    init(paths: [String: PathState]) {
        self._paths = paths
        self._isSinglePath = false
    }

    /// Single-path (wildcard) initializer.
    init(singlePath: PathState) {
        self._paths = [Self.wildcardKey: singlePath]
        self._isSinglePath = true
    }

    /// Look up the `PathState` to use for an incoming request URI.
    /// In single-path mode this always returns the wildcard state.
    func state(for uri: String) -> PathState? {
        if _isSinglePath {
            return lock.withLock { _paths[Self.wildcardKey] }
        }
        // Strip query string if present; paths are registered without it.
        let path = uri.split(separator: "?", maxSplits: 1).first.map(String.init) ?? uri
        return lock.withLock { _paths[path] }
    }

    func setState(_ state: PathState, for path: String) {
        lock.withLock { _paths[path] = state }
    }

    var requests: [ReceivedRequest] { lock.withLock { _requests } }

    func recordRequest(_ r: ReceivedRequest) {
        lock.withLock { _requests.append(r) }
    }

    func requests(forURIPrefix prefix: String) -> [ReceivedRequest] {
        lock.withLock { _requests.filter { $0.uri.hasPrefix(prefix) } }
    }

    func clearRequests() {
        lock.withLock { _requests.removeAll() }
    }

    // MARK: Single-path convenience accessors
    //
    // These proxy to the wildcard `PathState` and are intended for the
    // single-path convenience API only. Calling them on a multi-path
    // server will trap.

    private var singlePathState: PathState {
        guard _isSinglePath, let s = lock.withLock({ _paths[Self.wildcardKey] }) else {
            preconditionFailure(
                "Single-path accessors are only valid on servers started via start(bundleData:...)"
            )
        }
        return s
    }

    var bundleData: Data {
        get { singlePathState.data }
        set { singlePathState.data = newValue }
    }
    var etag: String? {
        get { singlePathState.etag }
        set { singlePathState.etag = newValue }
    }
    var forceStatusCode: UInt? {
        get { singlePathState.forceStatusCode }
        set { singlePathState.forceStatusCode = newValue }
    }
    var responseContentType: String {
        get { singlePathState.contentType }
        set { singlePathState.contentType = newValue }
    }
}

// MARK: - Handler

/// NIO channel handler that implements ETag-aware bundle serving across
/// one or many paths.
///
/// Behaviour (per resolved `PathState`):
///  - If `forceStatusCode` is set, respond with that code (304 still honors etag header).
///  - If the incoming `If-None-Match` header matches the current ETag, respond 304.
///  - Otherwise respond 200 with the current data and ETag.
///  - If `longPollDelay` is set, the response is scheduled after that delay.
final class TestBundleHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    let state: ServerState
    private var requestHead: HTTPRequestHead?

    init(state: ServerState) {
        self.state = state
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)

        switch part {
        case .head(let head):
            requestHead = head
        case .body:
            break
        case .end:
            guard let head = requestHead else { return }

            // Record every request for later inspection.
            let headers = head.headers.map { (name: $0.name, value: $0.value) }
            state.recordRequest(
                ReceivedRequest(
                    method: head.method.rawValue,
                    uri: head.uri,
                    headers: headers
                ))

            // Resolve per-path state. If the path isn't registered, 404.
            guard let pathState = state.state(for: head.uri) else {
                let body = Data("not found".utf8)
                var responseHead = HTTPResponseHead(version: head.version, status: .notFound)
                responseHead.headers.add(name: "content-length", value: "\(body.count)")
                context.write(wrapOutboundOut(.head(responseHead)), promise: nil)
                var buffer = context.channel.allocator.buffer(capacity: body.count)
                buffer.writeBytes(body)
                context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
                context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
                requestHead = nil
                return
            }

            if let delay = pathState.longPollDelay {
                let ms = Int64(delay.components.seconds * 1000)
                let headCopy = head
                let contextCopy = context
                context.eventLoop.scheduleTask(in: .milliseconds(ms)) { [weak self] in
                    guard let self else { return }
                    self.writeResponse(context: contextCopy, head: headCopy, pathState: pathState)
                }
            } else {
                writeResponse(context: context, head: head, pathState: pathState)
            }

            requestHead = nil
        }
    }

    private func writeResponse(
        context: ChannelHandlerContext,
        head: HTTPRequestHead,
        pathState: PathState
    ) {
        let forceCode = pathState.forceStatusCode
        let currentETag = pathState.etag
        let ifNoneMatch = head.headers["if-none-match"].first

        let shouldReturn304: Bool = {
            if let forceCode {
                return forceCode == 304
            }
            guard let ifNoneMatch, let currentETag else { return false }
            return ifNoneMatch == currentETag
        }()

        if shouldReturn304 {
            var responseHead = HTTPResponseHead(version: head.version, status: .notModified)
            if let currentETag {
                responseHead.headers.add(name: "etag", value: currentETag)
            }
            context.write(wrapOutboundOut(.head(responseHead)), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        } else if let forceCode, forceCode != 304 {
            let status = HTTPResponseStatus(statusCode: Int(forceCode))
            let responseHead = HTTPResponseHead(version: head.version, status: status)
            context.write(wrapOutboundOut(.head(responseHead)), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        } else {
            var responseHead = HTTPResponseHead(version: head.version, status: .ok)
            responseHead.headers.add(name: "content-type", value: pathState.contentType)
            if let etag = currentETag {
                responseHead.headers.add(name: "etag", value: etag)
            }

            let body = pathState.data
            responseHead.headers.add(name: "content-length", value: "\(body.count)")

            context.write(wrapOutboundOut(.head(responseHead)), promise: nil)
            var buffer = context.channel.allocator.buffer(capacity: body.count)
            buffer.writeBytes(body)
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        }
    }
}
