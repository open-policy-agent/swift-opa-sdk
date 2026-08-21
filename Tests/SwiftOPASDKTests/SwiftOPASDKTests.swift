import Foundation
// Plain (non-@testable) import: this is exactly what an external consumer of
// the `SwiftOPASDK` product sees. It compiles only because the umbrella module
// re-exports `Runtime`, `Config`, `Rego`, and `Logging`.
import SwiftOPASDK
import Testing

// A mock bundle loader that returns a canned in-memory bundle, ensuring the
// `bundleLoaders:` injection route is reachable and usable from the product.
extension OPA {
    struct CannedBundleLoader: OPA.BundleLoader {
        init(config: OPA.Config, bundleResourceName: String, logger: Logger?) throws {}

        func load() async -> Result<OPA.Bundle, any Error> {
            do {
                return .success(try OPA.Bundle())
            } catch {
                return .failure(error)
            }
        }

        static func compatibleWithConfig(config: OPA.Config, bundleResourceName: String) -> Bool {
            true
        }
    }
}

@Suite("SwiftOPASDK public surface")
struct SwiftOPASDKPublicSurfaceTests {

    @Test("core public types are reachable through the umbrella product")
    func publicTypesAreReachable() {
        // Referencing these compiles only if the re-export exposes them.
        let _: OPA.HTTPClientConfigSource? = nil
        let _: OPA.DiskBasedBundleLoader.Type = OPA.DiskBasedBundleLoader.self
        let _: OPA.RESTClientBundleLoader.Type = OPA.RESTClientBundleLoader.self
        let _: (any OPA.ConfigProvider)? = nil
        // The cache type is referenced only by name (its init/methods are
        // internal; consumers control it via Runtime's evict* methods).
        let _: OPA.HTTPClientCache.Type = OPA.HTTPClientCache.self
    }

    @Test("a consumer can inject a mock BundleLoader and load a bundle without network")
    func mockLoaderInjection() async throws {
        let configJSON = """
            {
              "services": {"svc": {"url": "https://example.com"}},
              "bundles": {"test": {"service": "svc", "resource": "/bundles/test"}}
            }
            """
        let config = try JSONDecoder().decode(OPA.Config.self, from: Data(configJSON.utf8))

        let runtime = try OPA.Runtime(
            config: config,
            bundleLoaders: [OPA.CannedBundleLoader.self])

        let runTask = Task { try await runtime.run() }

        var loaded = false
        for _ in 0..<100 {
            if runtime.bundleStorage["test"] != nil {
                loaded = true
                break
            }
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(loaded, "the injected mock loader's bundle should reach bundle storage")

        // Manual cache-control API is reachable too.
        runtime.evictAllCachedHTTPClients()

        // Await teardown so run()'s shutdownAll() completes before the test returns.
        runTask.cancel()
        _ = try? await runTask.value
    }
}
