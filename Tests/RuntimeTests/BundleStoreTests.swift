import Foundation
import Rego
import Testing

@testable import Runtime

// Pure, deterministic tests of the single activation boundary. No network, no
// Runtime — just the transition table for `update`/`remove` with injected clocks.

@Suite("BundleStore activation boundary")
struct BundleStoreTests {
    // Fixed, ascending timestamps for deterministic clock assertions.
    let t0 = Date(timeIntervalSince1970: 1_000_000)
    let t1 = Date(timeIntervalSince1970: 1_000_060)
    let t2 = Date(timeIntervalSince1970: 1_000_120)

    @Test("fresh download activates: sets live, all success clocks, and generation")
    func freshDownloadActivates() throws {
        var store = OPA.BundleStore()
        let b = try makeExampleBundle()

        let changed = store.update(name: "x", .downloaded(b, etag: "\"v1\"", size: 42), now: t0)

        #expect(changed)
        #expect(store.generation == 1)
        #expect(store.bundles["x"] == b)
        #expect(store.live["x"]?.bundle == b)
        #expect(store.live["x"]?.revision == b.manifest.revision)
        let f = store.fetch["x"]
        #expect(f?.lastRequest == t0)
        #expect(f?.lastSuccessfulRequest == t0)
        #expect(f?.lastSuccessfulDownload == t0)
        #expect(f?.etag == "\"v1\"")
        #expect(f?.size == 42)
        #expect(f?.type == "snapshot")
        #expect(f?.code == nil)
        let status = store.activeBundles()["x"]
        #expect(status?.bundle == b)
        #expect(status?.metadata.activeRevision == b.manifest.revision)
        #expect(status?.metadata.lastSuccessfulActivation == t0)
    }

    @Test("byte-identical re-download advances the download clock but not activation/generation")
    func sameContentReDownload() throws {
        var store = OPA.BundleStore()
        let b = try makeExampleBundle()
        _ = store.update(name: "x", .downloaded(b, etag: "\"v1\"", size: 10), now: t0)

        let changed = store.update(name: "x", .downloaded(b, etag: "\"v1\"", size: 10), now: t1)

        #expect(!changed)
        #expect(store.generation == 1)  // unchanged: same content
        #expect(store.fetch["x"]?.lastSuccessfulDownload == t1)  // advanced (a download happened)
        #expect(store.fetch["x"]?.lastSuccessfulRequest == t1)
        #expect(store.live["x"]?.lastSuccessfulActivation == t0)  // unchanged: no new activation
        #expect(store.activeBundles()["x"]?.bundle == b)
    }

    @Test("new content re-activates and bumps generation")
    func newContentReactivates() throws {
        var store = OPA.BundleStore()
        let b1 = try makeExampleBundle()
        let b2 = try makeExampleBundle()
        _ = store.update(name: "x", .downloaded(b1, etag: "\"v1\"", size: 1), now: t0)

        let changed = store.update(name: "x", .downloaded(b2, etag: "\"v2\"", size: 2), now: t1)

        #expect(changed)
        #expect(store.generation == 2)
        #expect(store.bundles["x"] == b2)
        #expect(store.live["x"]?.revision == b2.manifest.revision)
        #expect(store.live["x"]?.lastSuccessfulActivation == t1)
        #expect(store.fetch["x"]?.etag == "\"v2\"")
    }

    @Test("304 advances the request clock only and keeps the live bundle")
    func notModifiedKeepsLive() throws {
        var store = OPA.BundleStore()
        let b = try makeExampleBundle()
        _ = store.update(name: "x", .downloaded(b, etag: "\"v1\"", size: 1), now: t0)

        let changed = store.update(name: "x", .notModified(etag: "\"v1\""), now: t1)

        #expect(!changed)
        #expect(store.generation == 1)
        #expect(store.activeBundles()["x"]?.bundle == b)
        let f = store.fetch["x"]
        #expect(f?.lastRequest == t1)
        #expect(f?.lastSuccessfulRequest == t1)  // advanced
        #expect(f?.lastSuccessfulDownload == t0)  // unchanged: no fresh download
        #expect(store.live["x"]?.lastSuccessfulActivation == t0)  // unchanged
        #expect(f?.code == nil)
    }

    @Test("304 with nothing active records a defensive error and does not activate")
    func notModifiedNoPriorLive() {
        var store = OPA.BundleStore()

        let changed = store.update(name: "x", .notModified(etag: nil), now: t0)

        #expect(!changed)
        #expect(store.generation == 0)
        #expect(store.live["x"] == nil)
        #expect(store.fetch["x"]?.code != nil)
        #expect(store.fetch["x"]?.httpCode == 304)
        #expect(store.activeBundles()["x"]?.bundle == nil)
    }

    @Test("failure after success keeps the bundle live and records the error (the fix)")
    func failureKeepsBundleLive() throws {
        var store = OPA.BundleStore()
        let b = try makeExampleBundle()
        _ = store.update(name: "x", .downloaded(b, etag: "\"v1\"", size: 7), now: t0)

        let err = BundleFetchError(code: .bundleLoadError, message: "boom", httpStatus: 503, host: "h")
        let changed = store.update(name: "x", .failed(err), now: t1)

        #expect(!changed)
        #expect(store.generation == 1)  // unchanged: the active set is intact
        #expect(store.bundles["x"] == b)  // still enforced
        #expect(store.live["x"]?.bundle == b)
        #expect(store.live["x"]?.revision == b.manifest.revision)
        let f = store.fetch["x"]
        #expect(f?.lastRequest == t1)  // advanced: a poll happened
        #expect(f?.lastSuccessfulRequest == t0)  // unchanged
        #expect(f?.lastSuccessfulDownload == t0)  // unchanged
        #expect(f?.etag == "\"v1\"")  // retained across the failure
        #expect(f?.code == "bundleLoadError")
        #expect(f?.message == "boom")
        #expect(f?.httpCode == 503)
        // "loaded, and the most recent refresh failed" — distinguishable from
        // "never loaded".
        let status = store.activeBundles()["x"]
        #expect(status?.bundle == b)
        #expect(status?.metadata.code == "bundleLoadError")
        #expect(status?.metadata.lastRequest == t1)
        #expect(status?.metadata.lastSuccessfulActivation == t0)
    }

    @Test("failure with nothing loaded: no live bundle, error recorded (never-loaded state)")
    func failureNoPriorLive() {
        var store = OPA.BundleStore()

        let err = RuntimeError(code: .bundleTransportError, message: "dns")
        let changed = store.update(name: "x", .failed(err), now: t0)

        #expect(!changed)
        #expect(store.generation == 0)
        #expect(store.live["x"] == nil)
        #expect(store.bundles["x"] == nil)
        let status = store.activeBundles()["x"]
        #expect(status?.bundle == nil)  // never loaded
        #expect(status?.metadata.code == "bundleTransportError")
    }

    @Test("a successful poll clears a previously recorded error")
    func successClearsError() throws {
        var store = OPA.BundleStore()
        _ = store.update(name: "x", .failed(RuntimeError(code: .bundleLoadError, message: "boom")), now: t0)
        #expect(store.fetch["x"]?.code != nil)

        let b = try makeExampleBundle()
        _ = store.update(name: "x", .downloaded(b, etag: "\"v1\"", size: 1), now: t1)

        #expect(store.fetch["x"]?.code == nil)
        #expect(store.activeBundles()["x"]?.metadata.code == nil)
    }

    @Test("remove drops a live bundle and bumps generation")
    func removeLive() throws {
        var store = OPA.BundleStore()
        let b = try makeExampleBundle()
        _ = store.update(name: "x", .downloaded(b, etag: "\"v1\"", size: 1), now: t0)

        let removed = store.remove(["x"])

        #expect(removed)
        #expect(store.generation == 2)  // 1 (activate) -> 2 (remove)
        #expect(store.live["x"] == nil)
        #expect(store.bundles["x"] == nil)
        #expect(store.fetch["x"] == nil)
        #expect(store.activeBundles()["x"] == nil)
    }

    @Test("remove of a failure-only entry drops it without bumping generation")
    func removeFetchOnly() {
        var store = OPA.BundleStore()
        _ = store.update(name: "x", .failed(RuntimeError(code: .bundleLoadError, message: "boom")), now: t0)
        #expect(store.generation == 0)

        let removed = store.remove(["x"])

        #expect(removed)
        #expect(store.generation == 0)  // no live entry -> no rebuild needed
        #expect(store.fetch["x"] == nil)
        #expect(store.activeBundles()["x"] == nil)
    }

    @Test("remove of an unknown name is a no-op")
    func removeUnknown() {
        var store = OPA.BundleStore()
        let removed = store.remove(["nope"])
        #expect(!removed)
        #expect(store.generation == 0)
    }

    @Test("an empty etag surfaces as nil in the status metadata")
    func emptyEtagIsNilInMetadata() throws {
        var store = OPA.BundleStore()
        let b = try makeExampleBundle()
        _ = store.update(name: "x", .downloaded(b, etag: nil, size: nil), now: t0)
        #expect(store.activeBundles()["x"]?.metadata.etag == nil)
    }
}
