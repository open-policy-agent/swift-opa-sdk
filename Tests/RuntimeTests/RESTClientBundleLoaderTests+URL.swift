import Foundation
import Rego
import Testing

@Suite("RESTClientBundleLoader fetchURL construction")
struct RESTClientBundleLoaderURLTests {

    @Test("Resource without a query string appends as a path")
    func testPlainPathResource() throws {
        let loader = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(
                baseURL: "https://example.com/opa/v1",
                resourcePath: "/bundles/test.tar.gz"
            )
        )
        #expect(loader.fetchURL.absoluteString == "https://example.com/opa/v1/bundles/test.tar.gz")
    }

    @Test("Resource with a query string preserves the '?' separator")
    func testResourceWithQueryString() throws {
        // Regression: URL.appending(path:) percent-encodes '?' to %3F,
        // which turns a query string into part of the path and breaks
        // server-side routing for endpoints like `discovery?foo=bar`.
        let loader = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(
                baseURL: "https://example.com/opa/v1",
                resourcePath: "discovery?foo=bar"
            )
        )
        #expect(loader.fetchURL.absoluteString == "https://example.com/opa/v1/discovery?foo=bar")
        #expect(!loader.fetchURL.absoluteString.contains("%3F"))
    }

    @Test("Resource with a fragment preserves the '#' separator")
    func testResourceWithFragment() throws {
        let loader = try makeRESTClientBundleLoader(
            configJSON: makeETagTestConfig(
                baseURL: "https://example.com/opa/v1",
                resourcePath: "bundles/test.tar.gz#section"
            )
        )
        #expect(loader.fetchURL.absoluteString == "https://example.com/opa/v1/bundles/test.tar.gz#section")
        #expect(!loader.fetchURL.absoluteString.contains("%23"))
    }
}
