import Foundation
import Rego
import Testing

@testable import Runtime

// MARK: - Programmatically-Injected Header Tests

/// Covers the `OPA.Runtime` and `DiscoveryConfigProvider`` header fields.
@Suite("RuntimeInjectedHeaderTests")
struct RuntimeInjectedHeaderTests {

    // MARK: - Regular bundle fetches

    @Test("injected headers appear on outbound bundle fetch requests")
    func testInjectedHeadersReachBundleFetch() async throws {
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        let server = try await TestBundleServer.start(files: [
            "/bundles/test.tar.gz": bundleData
        ])
        defer { Task { try? await server.shutdown() } }

        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfig(baseURL: server.baseURL).utf8))
        let rt = try OPA.Runtime(
            config: config,
            headers: ["x-injected": "hello", "x-tenant": "acme"])
        #expect(rt.headers == ["x-injected": "hello", "x-tenant": "acme"])

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }

        let result = try #require(
            await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(10)),
            "bundle never loaded")
        _ = try requireBundleLoadSuccess(result)

        let request = try #require(server.state.requests.first, "server saw no requests")
        #expect(request.headerValue(for: "x-injected") == "hello")
        #expect(request.headerValue(for: "x-tenant") == "acme")
    }

    @Test("no injected headers: outbound request carries none")
    func testNoInjectedHeaders() async throws {
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        let server = try await TestBundleServer.start(files: [
            "/bundles/test.tar.gz": bundleData
        ])
        defer { Task { try? await server.shutdown() } }

        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfig(baseURL: server.baseURL).utf8))
        let rt = try OPA.Runtime(config: config)
        #expect(rt.headers == nil)

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }

        let result = try #require(
            await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(10)),
            "bundle never loaded")
        _ = try requireBundleLoadSuccess(result)

        let request = try #require(server.state.requests.first, "server saw no requests")
        #expect(request.headerValue(for: "x-injected") == nil)
    }

    // MARK: - Service-config headers & precedence

    @Test("service-config headers still apply and injected headers win on conflict")
    func testServiceHeadersAndPrecedence() async throws {
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        let server = try await TestBundleServer.start(files: [
            "/bundles/test.tar.gz": bundleData
        ])
        defer { Task { try? await server.shutdown() } }

        // `x-shared` is set by BOTH the service config and the injected
        // headers. `RESTClientBundleLoader.load()` merges service headers
        // first, then lets `customHeaders` win, so the injected value must
        // be the one sent out.
        let configJSON = """
            {
              "services": {
                "test-svc": {
                  "url": "\(server.baseURL)",
                  "headers": {
                    "x-from-service": "service-only",
                    "x-shared": "service-value"
                  }
                }
              },
              "bundles": {
                "test": {"service": "test-svc", "resource": "/bundles/test.tar.gz"}
              }
            }
            """
        let config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))
        let rt = try OPA.Runtime(
            config: config,
            headers: ["x-injected": "injected-only", "x-shared": "injected-value"])

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }

        let result = try #require(
            await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(10)),
            "bundle never loaded")
        _ = try requireBundleLoadSuccess(result)

        let request = try #require(server.state.requests.first, "server saw no requests")
        #expect(
            request.headerValue(for: "x-from-service") == "service-only",
            "service-config headers must still be sent")
        #expect(
            request.headerValue(for: "x-injected") == "injected-only",
            "injected headers must be sent alongside service headers")
        #expect(
            request.headerValue(for: "x-shared") == "injected-value",
            "injected headers must win over service-config headers on conflict")
        #expect(
            request.allHeaderValues(for: "x-shared") == ["injected-value"],
            "conflicting header must be replaced, not duplicated")
    }

    @Test("an injected Accept header overrides the loader's default IR Accept value")
    func testInjectedAcceptOverridesDefault() async throws {
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        let server = try await TestBundleServer.start(files: [
            "/bundles/test.tar.gz": bundleData
        ])
        defer { Task { try? await server.shutdown() } }

        // Ensure injected headers win over defaults.
        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfig(baseURL: server.baseURL).utf8))
        let rt = try OPA.Runtime(
            config: config,
            headers: ["Accept": "application/gzip"])

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }

        let result = try #require(
            await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(10)),
            "bundle never loaded")
        _ = try requireBundleLoadSuccess(result)

        let request = try #require(server.state.requests.first, "server saw no requests")
        #expect(
            request.headerValue(for: "Accept") == "application/gzip",
            "injected Accept must override the default IR Accept header")
        #expect(
            request.allHeaderValues(for: "Accept") == ["application/gzip"],
            "Accept must be replaced, not appended to")
    }

    @Test("without an injected Accept, the default IR Accept header is still sent")
    func testDefaultAcceptSurvivesUnrelatedInjectedHeaders() async throws {
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle())
        let server = try await TestBundleServer.start(files: [
            "/bundles/test.tar.gz": bundleData
        ])
        defer { Task { try? await server.shutdown() } }

        // Guards the inverse of the test above: injecting unrelated headers
        // must not disturb the IR content negotiation the loader performs.
        let config = try JSONDecoder().decode(
            OPA.Config.self,
            from: Data(makeETagTestConfig(baseURL: server.baseURL).utf8))
        let rt = try OPA.Runtime(config: config, headers: ["x-tenant": "acme"])

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }

        let result = try #require(
            await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(10)),
            "bundle never loaded")
        _ = try requireBundleLoadSuccess(result)

        let request = try #require(server.state.requests.first, "server saw no requests")
        #expect(request.headerValue(for: "x-tenant") == "acme")
        #expect(
            request.headerValue(for: "Accept") == OPA.RESTClientBundleLoader.defaultAcceptHeader,
            "the default IR Accept header must survive unrelated injected headers")
    }

    // MARK: - Discovery

    @Test("injected headers reach the discovery bundle fetch and discovered bundles")
    func testInjectedHeadersReachDiscoveryFetch() async throws {
        let (server, runtime, runTask) = try await startDiscoveryRuntime(
            discovery: DiscoverySpec(discoveredBundles: ["b1"]),
            bundles: [BundleSpec(name: "b1")],
            headers: ["x-injected": "disco-hello"]
        )
        defer {
            runTask.cancel()
            Task { try? await server.shutdown() }
        }

        try await waitForRequests(server, prefix: "/discovery", atLeast: 1)
        let discoveryRequest = try #require(
            server.state.requests(forURIPrefix: "/discovery").first,
            "server saw no /discovery requests")
        #expect(
            discoveryRequest.headerValue(for: "x-injected") == "disco-hello",
            "injected headers must reach the discovery bundle fetch")

        // Bundles discovered *via* discovery are loaded by the Runtime's own
        // loaders, so they must carry the injected headers too.
        try await waitForBundleCount(runtime, atLeast: 1, timeout: .seconds(15))
        expectBundleSucceeded(await runtime.storageSnapshot(), "b1")

        try await waitForRequests(server, prefix: "/bundles/b1", atLeast: 1)
        let bundleRequest = try #require(
            server.state.requests(forURIPrefix: "/bundles/b1").first,
            "server saw no /bundles/b1 requests")
        #expect(
            bundleRequest.headerValue(for: "x-injected") == "disco-hello",
            "injected headers must reach discovered bundle fetches")
    }

    @Test("DiscoveryConfigProvider headers param reaches the discovery fetch")
    func testDiscoveryConfigProviderHeadersParam() async throws {
        // Stand up a /discovery endpoint serving a real discovery bundle so
        // `load()` succeeds end-to-end, not just at the HTTP layer.
        let server = try await TestBundleServer.start(paths: [
            "/discovery": PathState(data: Data(), etag: nil)
        ])
        defer { Task { try? await server.shutdown() } }

        let discoveryBundle = try makeDiscoveryBundle(
            decisionPath: "discovery/config",
            configDataPath: "discovery/config",
            configJSON: discoveryConfigJSON(bundleNames: ["b1"], serviceURL: server.baseURL)
        )
        server.state.state(for: "/discovery")?.data =
            try OPA.Bundle.encodeToTarball(bundle: discoveryBundle)

        let bootConfigJSON = """
            {
                "services": {"svc": {"url": "\(server.baseURL)"}},
                "discovery": {
                    "service": "svc",
                    "resource": "/discovery",
                    "decision": "discovery/config"
                }
            }
            """
        let bootConfig = try JSONDecoder().decode(
            OPA.Config.self, from: Data(bootConfigJSON.utf8))

        var provider = try OPA.DiscoveryConfigProvider(
            bootConfig: bootConfig,
            headers: ["x-provider-injected": "yes"])
        let result = await provider.load()

        guard case .success(let merged) = result else {
            Issue.record("expected discovery load to succeed, got \(result)")
            return
        }
        #expect(merged.bundles["b1"] != nil, "discovered config should list b1")

        let request = try #require(
            server.state.requests(forURIPrefix: "/discovery").first,
            "server saw no /discovery requests")
        #expect(request.headerValue(for: "x-provider-injected") == "yes")
    }

    // MARK: - Non-HTTP loader fallback

    @Test("DiskBasedBundleLoader still loads via the non-HTTP fallback branch")
    func testDiskBasedLoaderFallbackStillWorks() async throws {
        let tempDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let bundleURL = tempDir.appendingPathComponent("bundle.tar.gz")
        try OPA.Bundle.encodeToTarball(bundle: makeExampleBundle()).write(to: bundleURL)

        let configJSON = #"""
            {
              "bundles": {
                "test": {"resource": "file:///{TEMP}/bundle.tar.gz"}
              }
            }
            """#.replacingOccurrences(of: "{TEMP}", with: tempDir.path())
        let config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))

        // `DiskBasedBundleLoader` is a plain `BundleLoader`, supplying headers
        // must not break loader selection or construction.
        let rt = try OPA.Runtime(config: config, headers: ["x-injected": "ignored-by-disk-loader"])

        let loader = try rt.getBundleLoader(name: "test", config: config, logger: rt.logger)
        #expect(
            loader is OPA.DiskBasedBundleLoader,
            "expected DiskBasedBundleLoader, got \(type(of: loader))")

        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }

        let result = try #require(
            await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(10)),
            "bundle never loaded")
        _ = try requireBundleLoadSuccess(result)

        let dr = try await rt.decision("data/foo/hello", input: nil)
        #expect(dr.result.first == ["result": 1])
    }

    @Test("HTTP loader is built through the HTTP init and carries injected headers")
    func testRESTLoaderConstructedViaHTTPInit() async throws {
        let configJSON = makeETagTestConfig(baseURL: "https://example.com")
        let config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))
        let rt = try OPA.Runtime(config: config, headers: ["x-injected": "hello"])

        let loader = try rt.getBundleLoader(name: "test", config: config, logger: rt.logger)
        let restLoader = try #require(
            loader as? OPA.RESTClientBundleLoader,
            "expected RESTClientBundleLoader, got \(type(of: loader))")
        #expect(restLoader.customHeaders == ["x-injected": "hello"])
    }
}
