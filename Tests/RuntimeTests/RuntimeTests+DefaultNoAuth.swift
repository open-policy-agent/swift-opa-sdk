import Foundation
import Rego
import Testing

@testable import Runtime

// MARK: - Default No Auth HTTP Bundle Tests

@Suite("RuntimeHTTPBundleDefaultNoAuthTests")
struct RuntimeHHTTPBundleDefaultNoAuthTests {
    // MARK: - Valid HTTP Cases
    @Test("simple HTTP service with tarball bundle")
    func testValidHTTPBundle() async throws {
        let testBundle = try makeExampleBundle()
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: testBundle)

        let server = try await TestBundleServer.start(files: [
            "/bundles/bundle.tar.gz": bundleData
        ])
        defer { Task { try? await server.shutdown() } }

        let configJSON = """
            {
              "services": {"test-svc": {"url": "\(server.baseURL)"}},
              "bundles": {
                "test": {"service": "test-svc", "resource": "/bundles/bundle.tar.gz"}
              }
            }
            """

        let config = try JSONDecoder().decode(OPA.Config.self, from: configJSON.data(using: .utf8)!)
        let rt = try OPA.Runtime(config: config)

        let backgroundFetchTask = Task { try await rt.run() }
        defer { backgroundFetchTask.cancel() }

        let _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(1))
        let bundleStorage = rt.activeBundles()
        let bundleResult = try #require(
            bundleStorage.first, "Expected exactly 1 bundle, got \(bundleStorage.count)")
        #expect(bundleStorage.count == 1, "Expected exactly 1 bundle, got \(bundleStorage.count)")
        guard bundleResult.value.bundle != nil else {
            Issue.record("Expected bundle '\(bundleResult.key)' to be loaded, got \(bundleResult.value)")
            return
        }
        #expect(bundleStorage.allSatisfy { $0.value.bundle != nil })

        let dr = try await rt.decision("data/foo/hello", input: nil)
        #expect(dr.result.first == ["result": 1])
    }

    @Test("HTTP service with custom resource path")
    func testValidHTTPBundleCustomPath() async throws {
        let testBundle = try makeExampleBundle()
        let bundleData = try OPA.Bundle.encodeToTarball(bundle: testBundle)

        let server = try await TestBundleServer.start(files: [
            "/custom/path/my-bundle.tar.gz": bundleData
        ])
        defer { Task { try? await server.shutdown() } }

        let configJSON = """
            {
              "services": {"my-service": {"url": "\(server.baseURL)"}},
              "bundles": {
                "test": {"service": "my-service", "resource": "/custom/path/my-bundle.tar.gz"}
              }
            }
            """

        let config = try JSONDecoder().decode(OPA.Config.self, from: configJSON.data(using: .utf8)!)
        let rt = try OPA.Runtime(config: config)

        let backgroundFetchTask = Task { try await rt.run() }
        defer { backgroundFetchTask.cancel() }

        let _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(1))
        let bundleStorage = rt.activeBundles()
        let bundleResult = try #require(
            bundleStorage.first, "Expected exactly 1 bundle, got \(bundleStorage.count)")
        #expect(bundleStorage.count == 1, "Expected exactly 1 bundle, got \(bundleStorage.count)")
        guard bundleResult.value.bundle != nil else {
            Issue.record("Expected bundle '\(bundleResult.key)' to be loaded, got \(bundleResult.value)")
            return
        }

        let dr = try await rt.decision("data/foo/hello", input: nil)
        #expect(dr.result.first == ["result": 1])
    }

    // MARK: - Invalid HTTP Cases
    @Test("HTTP service returns 404 for bundle path")
    func testHTTPBundle404() async throws {
        // Server is running but has no files — every request gets 404
        let server = try await TestBundleServer.start(files: [:])
        defer { Task { try? await server.shutdown() } }

        let configJSON = """
            {
              "services": {"test-svc": {"url": "\(server.baseURL)"}},
              "bundles": {
                "test": {"service": "test-svc", "resource": "/bundles/nonexistent.tar.gz"}
              }
            }
            """

        let config = try JSONDecoder().decode(OPA.Config.self, from: configJSON.data(using: .utf8)!)
        let rt = try OPA.Runtime(config: config)

        let backgroundFetchTask = Task { try await rt.run() }
        defer { backgroundFetchTask.cancel() }

        let _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(1))
        let bundleStorage = rt.activeBundles()
        #expect(bundleStorage.count == 1)
        #expect(
            bundleStorage.allSatisfy { $0.value.bundle == nil },
            "Expected bundle load to fail for 404 response")
    }

    @Test("service URL with invalid scheme fails config decode")
    func testInvalidServiceScheme() async throws {
        let configJSON = """
            {
              "services": {"bad-svc": {"url": "ftp://example.com"}},
              "bundles": {
                "test": {"service": "bad-svc", "resource": "/bundle.tar.gz"}
              }
            }
            """
        #expect(throws: (any Error).self) {
            _ = try JSONDecoder().decode(OPA.Config.self, from: configJSON.data(using: .utf8)!)
        }
    }
}
