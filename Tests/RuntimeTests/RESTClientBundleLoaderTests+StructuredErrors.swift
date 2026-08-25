import Foundation
import Rego
import Testing

@testable import Runtime

// MARK: - Structured fetch-error tests
//
// These assert on the structured fields of `BundleFetchError` (code / httpStatus
// / host)

@Suite("RESTClientBundleLoader Structured Error Tests")
struct RESTClientStructuredErrorTests {

    /// The host every `TestBundleServer` binds to.
    private let expectedHost = "127.0.0.1"

    @Test(
        "HTTP status is exposed on BundleFetchError.httpStatus",
        arguments: [404 as UInt, 422, 500]
    )
    func testHTTPStatusExposed(status: UInt) async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            server.state.forceStatusCode = status
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let error = try requireBundleLoadFailure(await loader.load())
            let fetchError = try #require(error as? BundleFetchError)

            #expect(fetchError.httpStatus == Int(status))
            #expect(fetchError.host == expectedHost)
            #expect(fetchError.code == .bundleLoadError)
        }
    }

    @Test("304 without a cached bundle exposes httpStatus 304 and host")
    func test304ExposesStatus() async throws {
        let server = try await TestBundleServer.start(
            bundleData: Data(), etag: "\"orphan\"", forceStatusCode: 304
        )
        defer { Task { try? await server.shutdown() } }

        var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

        let error = try requireBundleLoadFailure(await loader.load())
        let fetchError = try #require(error as? BundleFetchError)

        #expect(fetchError.httpStatus == 304)
        #expect(fetchError.host == expectedHost)
        #expect(fetchError.code == .bundleLoadError)
    }

    // A transport failure (network, DNS, TLS) can't be exercised over a real
    // socket without risking a hang: the loader's non-long-polling path uses a
    // `.distantFuture` deadline, so a stalled connect or DNS lookup never
    // returns. Instead, unit-test the mapping the loader's outer catch applies.
    @Test("Transport errors map to a nil-httpStatus, host-bearing BundleFetchError")
    func testTransportErrorMapping() throws {
        struct FakeNetworkError: Error {}
        let url = URL(string: "https://bundles.example.com/bundle.tar.gz")!

        let error = BundleFetchError.transport(url: url, cause: FakeNetworkError())

        #expect(error.httpStatus == nil)
        #expect(error.code == .bundleTransportError)
        #expect(error.host == "bundles.example.com")
        #expect(error.cause is FakeNetworkError)
        // Also readable through the shared protocol.
        #expect((error as any RuntimeFailure).code == .bundleTransportError)
    }

    @Test("An HTTP-status failure is readable through the RuntimeFailure protocol")
    func testHTTPStatusFailureThroughProtocol() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            server.state.forceStatusCode = 404
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))
            let error = try requireBundleLoadFailure(await loader.load())
            let failure = try #require(error as? any RuntimeFailure)
            #expect(failure.code == .bundleLoadError)
        }
    }

    @Test("Consecutive identical failures stringify identically (dedup contract)")
    func testDedupStability() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            server.state.forceStatusCode = 500
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let first = try requireBundleLoadFailure(await loader.load(), context: "first 500")
            let second = try requireBundleLoadFailure(await loader.load(), context: "second 500")

            #expect(String(describing: first) == String(describing: second))
        }
    }
}
