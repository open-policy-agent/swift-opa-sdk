import Foundation
import Rego
import Testing

// End-to-end tests of the `activeBundles()` / `activeBundleMetadata()` surface
// against the in-process ETag bundle server.

@Suite("Runtime activeBundles / status metadata")
struct RuntimeActiveBundlesTests {

    @Test("304 polls advance the request clock but not the download/activation clocks")
    func test304ClockDivergence() async throws {
        try await withBundleServer(etag: "\"ab-v1\"") { server in
            let configJSON = makeETagTestConfigWithPolling(baseURL: server.baseURL)
            try await withRunningRuntime(server: server, configJSON: configJSON) { rt in
                // Wait for the first successful load.
                _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(5))
                let first = try #require(rt.activeBundleMetadata()["test"])
                #expect(first.etag == "\"ab-v1\"")
                let firstDownload = try #require(first.lastSuccessfulDownload)
                let firstActivation = try #require(first.lastSuccessfulActivation)
                let firstRequest = try #require(first.lastSuccessfulRequest)

                // Let a few 1s-interval polls run. The stored ETag matches the
                // server's, so each poll returns 304.
                try await Task.sleep(for: .seconds(3))

                let later = try #require(rt.activeBundleMetadata()["test"])
                #expect(
                    rt.activeBundles()["test"]?.bundle != nil,
                    "the bundle stays enforced across 304 polls")
                #expect(later.activeRevision == first.activeRevision)
                #expect(later.lastSuccessfulDownload == firstDownload, "no fresh download on a 304")
                #expect(later.lastSuccessfulActivation == firstActivation, "no re-activation on a 304")
                let laterRequest = try #require(later.lastSuccessfulRequest)
                #expect(laterRequest > firstRequest, "the request clock advances on each 304")
                #expect(server.state.requests.count >= 2)
            }
        }
    }

    @Test("the ETag is surfaced and advances when the server serves new content")
    func testETagSurfacedAndAdvances() async throws {
        try await withBundleServer(etag: "\"ab-v1\"") { server in
            let configJSON = makeETagTestConfigWithPolling(baseURL: server.baseURL)
            try await withRunningRuntime(server: server, configJSON: configJSON) { rt in
                _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(5))
                let firstMeta = try #require(rt.activeBundleMetadata()["test"])
                #expect(firstMeta.etag == "\"ab-v1\"")
                let firstBundle = rt.bundles["test"]
                let firstActivation = try #require(firstMeta.lastSuccessfulActivation)

                // Serve new content under a new ETag.
                server.state.bundleData = try makeBundleData()
                server.state.etag = "\"ab-v2\""

                // Wait until the runtime activates the new content.
                let deadline = ContinuousClock.now + .seconds(6)
                while ContinuousClock.now < deadline {
                    if rt.activeBundleMetadata()["test"]?.etag == "\"ab-v2\"" { break }
                    try await Task.sleep(for: .milliseconds(100))
                }

                let updated = try #require(rt.activeBundleMetadata()["test"])
                #expect(updated.etag == "\"ab-v2\"", "the surfaced ETag advances with the new content")
                #expect(try #require(updated.lastSuccessfulActivation) > firstActivation)
                #expect(rt.bundles["test"] != firstBundle, "the new bundle is enforced")
            }
        }
    }

    @Test("a bundle whose source is missing is reported as not-activated with an error")
    func testMissingBundleReportedWithError() async throws {
        // A file:// source that does not exist fails every poll deterministically
        // (no network), so nothing is ever activated.
        let configJSON = """
            {"bundles": {"test": {"service": "", "resource": "file:///swift-opa-sdk-nonexistent/bundle.tar.gz"}}}
            """
        let config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))
        let rt = try OPA.Runtime(config: config)
        let backgroundTask = Task { try await rt.run() }
        defer { backgroundTask.cancel() }

        let meta = try #require(
            await waitForBundleError(rt: rt, name: "test", timeout: .seconds(5)),
            "expected an error to be recorded for the missing bundle")
        #expect(meta.code != nil)
        // Never loaded: no live bundle, distinguishable from a live bundle whose
        // refresh later failed.
        #expect(rt.activeBundles()["test"]?.bundle == nil)
        #expect(rt.bundles["test"] == nil)
    }
}
