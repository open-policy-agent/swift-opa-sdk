import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL

// MARK: - TLS Options

/// Optional TLS configuration for `TestBundleServer`. When present, the
/// server terminates TLS in front of the HTTP pipeline. Supplying
/// `clientCACertPath` makes the server require and validate a client
/// certificate (mTLS). For self-signed client certs, pass the client
/// cert itself here.
struct TestBundleServerTLSOptions: Sendable {
    let serverCertPath: String
    let serverKeyPath: String
    let clientCACertPath: String
}

// MARK: - Test HTTP(S) Server

/// A minimal HTTP(S) server for testing bundle downloads.
///
/// Analogous to Go's `httptest.NewServer`. Supports:
///   - Static URI -> `Data` mapping (see `start(files:tls:)`).
///   - Per-path `PathState` with ETag / `If-None-Match` / forced status
///     codes / long-poll delays (see `start(paths:tls:)`).
///   - Single-path "wildcard" mode for tests that don't care about routing
///     (see `start(bundleData:etag:...)`).
///   - TLS / mTLS termination in front of the HTTP pipeline.
///   - Request capture via `state.requests` for header assertions.
///
/// See `Utils+ETagBundleServer.swift` for `PathState`, `ServerState`, and
/// the channel handler implementation.
final class TestBundleServer: @unchecked Sendable {
    let port: Int
    let baseURL: String
    let state: ServerState

    private let channel: Channel
    private let group: EventLoopGroup

    private init(channel: Channel, group: EventLoopGroup, state: ServerState, isTLS: Bool) {
        self.channel = channel
        self.group = group
        self.state = state
        self.port = channel.localAddress!.port!
        let scheme = isTLS ? "https" : "http"
        self.baseURL = "\(scheme)://127.0.0.1:\(self.port)"
    }

    // MARK: - Public constructors

    /// Simple URI -> data mapping. Unlisted paths receive 404.
    /// Each path is served with the default content type (`application/gzip`)
    /// and no ETag / long-poll support.
    static func start(
        files: [String: Data],
        tls: TestBundleServerTLSOptions? = nil
    ) async throws -> TestBundleServer {
        let paths = files.mapValues { PathState(data: $0, etag: nil) }
        return try await start(state: ServerState(paths: paths), tls: tls)
    }

    /// Multi-path server. Each URI in `paths` is served from its own
    /// `PathState` (supports ETag, forced status codes, long-poll delays,
    /// per-path content type). Unregistered URIs receive 404.
    static func start(
        paths: [String: PathState],
        tls: TestBundleServerTLSOptions? = nil
    ) async throws -> TestBundleServer {
        return try await start(state: ServerState(paths: paths), tls: tls)
    }

    /// Single-path (wildcard) convenience. Every request, regardless of
    /// URI, is served from the same `PathState`. Useful for simple ETag /
    /// long-poll tests that don't care about routing.
    static func start(
        bundleData: Data,
        etag: String?,
        forceStatusCode: UInt? = nil,
        contentType: String = "application/gzip",
        tls: TestBundleServerTLSOptions? = nil
    ) async throws -> TestBundleServer {
        let ps = PathState(
            data: bundleData,
            etag: etag,
            forceStatusCode: forceStatusCode,
            contentType: contentType
        )
        return try await start(state: ServerState(singlePath: ps), tls: tls)
    }

    func shutdown() async throws {
        try await channel.close()
        try await group.shutdownGracefully()
    }

    // MARK: - Internal

    private static func start(
        state: ServerState,
        tls: TestBundleServerTLSOptions?
    ) async throws -> TestBundleServer {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

        // NIOSSLContext is thread-safe and may be shared across child channels.
        let sslContext: NIOSSLContext? = try tls.map { opts in
            let serverCerts = try NIOSSLCertificate.fromPEMFile(opts.serverCertPath)
            let serverKey = try NIOSSLPrivateKey(file: opts.serverKeyPath, format: .pem)
            let clientCAs = try NIOSSLCertificate.fromPEMFile(opts.clientCACertPath)

            var cfg = TLSConfiguration.makeServerConfiguration(
                certificateChain: serverCerts.map { .certificate($0) },
                privateKey: .privateKey(serverKey)
            )
            cfg.minimumTLSVersion = .tlsv12
            // Require & validate the client cert, but don't hostname-check
            // (servers can't meaningfully hostname-check their peer).
            cfg.certificateVerification = .noHostnameVerification
            cfg.trustRoots = .certificates(clientCAs)
            // Helps clients pick a cert when multiple are configured.
            cfg.sendCANameList = true
            return try NIOSSLContext(configuration: cfg)
        }

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let base: EventLoopFuture<Void> =
                    if let sslContext {
                        channel.pipeline.addHandler(NIOSSLServerHandler(context: sslContext))
                    } else {
                        channel.eventLoop.makeSucceededVoidFuture()
                    }
                return base.flatMap {
                    channel.pipeline.configureHTTPServerPipeline()
                }.flatMap {
                    channel.pipeline.addHandler(TestBundleHandler(state: state))
                }
            }

        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        return TestBundleServer(channel: channel, group: group, state: state, isTLS: tls != nil)
    }
}
