import Foundation
import Rego
import Runtime
import Testing

// MARK: - Accept Header / OPA IR Content Negotiation Tests

@Suite("RESTClientBundleLoader Accept Header Tests")
struct RESTClientAcceptHeaderTests {

    /// The exact value we expect to see.
    static let expectedAccept =
        "application/vnd.openpolicyagent.bundle.ir.v1+gzip;q=1.0, "
        + "application/vnd.openpolicyagent.bundles;q=0.9, "
        + "application/gzip;q=0.8, "
        + "*/*;q=0.1"

    /// Build an OPA config JSON with a `headers` block on the service.
    static func configWithServiceHeaders(
        baseURL: String,
        headers: [String: String],
        bundleName: String = "test",
        resourcePath: String = "/bundles/test.tar.gz"
    ) -> String {
        let headerEntries = headers.map { #""\#($0.key)": "\#($0.value)""# }.joined(separator: ", ")
        return """
            {
              "services": {
                "test-svc": {"url": "\(baseURL)", "headers": {\(headerEntries)}}
              },
              "bundles": {
                "\(bundleName)": {
                  "service": "test-svc",
                  "resource": "\(resourcePath)"
                }
              }
            }
            """
    }

    /// Build a discovery-flavored OPA config JSON.
    static func discoveryConfig(baseURL: String, resource: String = "/discovery") -> String {
        """
        {
          "services": {
            "test-svc": {"url": "\(baseURL)"}
          },
          "discovery": {
            "service": "test-svc",
            "resource": "\(resource)",
            "decision": "discovery/config"
          }
        }
        """
    }

    // MARK: Default Behavior

    @Test("The SDK constant matches the documented Accept header value")
    func testDefaultAcceptHeaderConstant() throws {
        #expect(OPA.RESTClientBundleLoader.defaultAcceptHeader == Self.expectedAccept)
    }

    @Test("A normal bundle fetch sends the IR-preferring Accept header")
    func testBundleFetchSendsAcceptHeader() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))
            let _ = try requireBundleLoadSuccess(await loader.load())

            let requests = server.state.requests
            #expect(requests.count == 1)
            #expect(requests[0].headerValue(for: "Accept") == Self.expectedAccept)
        }
    }

    @Test("Accept is sent exactly once (no duplicate header lines)")
    func testAcceptHeaderIsNotDuplicated() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))
            let _ = try requireBundleLoadSuccess(await loader.load())

            let values = server.state.requests[0].allHeaderValues(for: "Accept")
            #expect(values == [Self.expectedAccept])
        }
    }

    @Test("The discovery bundle fetch path also sends the Accept header")
    func testDiscoveryFetchSendsAcceptHeader() async throws {
        try await withBundleServer(etag: "\"disco-v1\"") { server in
            let config = try JSONDecoder().decode(
                OPA.Config.self,
                from: Data(Self.discoveryConfig(baseURL: server.baseURL).utf8)
            )
            var loader = try OPA.RESTClientBundleLoader(discoveryConfig: config)
            let _ = try requireBundleLoadSuccess(await loader.load(), context: "on discovery load")

            let requests = server.state.requests(forURIPrefix: "/discovery")
            #expect(requests.count == 1)
            #expect(requests[0].headerValue(for: "Accept") == Self.expectedAccept)
        }
    }

    // MARK: Operator Override

    @Test("An explicit Accept in services.<name>.headers overrides the default")
    func testServiceConfigAcceptWins() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            var loader = try makeRESTClientBundleLoader(
                configJSON: Self.configWithServiceHeaders(
                    baseURL: server.baseURL,
                    headers: ["Accept": "application/gzip"]
                )
            )
            let _ = try requireBundleLoadSuccess(await loader.load())

            let requests = server.state.requests
            #expect(requests.count == 1)
            #expect(requests[0].headerValue(for: "Accept") == "application/gzip")
            #expect(requests[0].allHeaderValues(for: "Accept") == ["application/gzip"])
        }
    }

    @Test("A lowercase 'accept' key in service headers also overrides the default")
    func testServiceConfigLowercaseAcceptWins() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            var loader = try makeRESTClientBundleLoader(
                configJSON: Self.configWithServiceHeaders(
                    baseURL: server.baseURL,
                    headers: ["accept": "application/vnd.openpolicyagent.bundles"]
                )
            )
            let _ = try requireBundleLoadSuccess(await loader.load())

            let requests = server.state.requests
            #expect(requests[0].allHeaderValues(for: "Accept") == ["application/vnd.openpolicyagent.bundles"])
        }
    }

    @Test("Unrelated service headers are preserved alongside the default Accept")
    func testUnrelatedServiceHeadersCoexist() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            var loader = try makeRESTClientBundleLoader(
                configJSON: Self.configWithServiceHeaders(
                    baseURL: server.baseURL,
                    headers: ["X-Custom": "hello"]
                )
            )
            let _ = try requireBundleLoadSuccess(await loader.load())

            let request = server.state.requests[0]
            #expect(request.headerValue(for: "X-Custom") == "hello")
            #expect(request.headerValue(for: "Accept") == Self.expectedAccept)
        }
    }

    // MARK: Interaction With ETag / Long-Polling

    @Test("Accept is still sent on the second, If-None-Match-bearing request")
    func testAcceptSentAlongsideIfNoneMatch() async throws {
        try await withBundleServer(etag: "\"v1\"") { server in
            var loader = try makeRESTClientBundleLoader(configJSON: makeETagTestConfig(baseURL: server.baseURL))

            let firstBundle = try requireBundleLoadSuccess(await loader.load(), context: "on first load")
            #expect(loader.etag == "\"v1\"")

            // Server replies 304 because If-None-Match matches its ETag.
            let secondBundle = try requireBundleLoadSuccess(await loader.load(), context: "on second (304) load")
            #expect(firstBundle == secondBundle)

            let requests = server.state.requests
            #expect(requests.count == 2)
            #expect(requests[1].headerValue(for: "If-None-Match") == "\"v1\"")
            #expect(requests[1].headerValue(for: "Accept") == Self.expectedAccept)
        }
    }

    @Test("Accept coexists with the long-polling Prefer header")
    func testAcceptSentAlongsideLongPollingPrefer() async throws {
        // The OPA bundle content type in the response enables long-polling
        // for the loader's *next* request.
        try await withBundleServer(
            etag: "\"lp-v1\"",
            contentType: "application/vnd.openpolicyagent.bundles"
        ) { server in
            var loader = try makeRESTClientBundleLoader(
                configJSON: makeETagTestConfigWithLongPolling(
                    baseURL: server.baseURL,
                    longPollingTimeoutSeconds: 5
                )
            )

            let _ = try requireBundleLoadSuccess(await loader.load(), context: "on first load")
            #expect(loader.isLongPollingEnabled())

            let _ = try requireBundleLoadSuccess(await loader.load(), context: "on second (long-poll) load")

            let requests = server.state.requests
            #expect(requests.count == 2)
            let prefer = requests[1].headerValue(for: "Prefer") ?? ""
            #expect(prefer.contains("wait=5"), "expected long-polling wait, got: \(prefer)")
            #expect(requests[1].headerValue(for: "Accept") == Self.expectedAccept)
        }
    }
}
