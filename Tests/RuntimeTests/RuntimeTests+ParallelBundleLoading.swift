import Foundation
import Rego
import Testing

@testable import Runtime

@Suite("ParallelBundleLoadingTests")
struct ParallelBundleLoadingTests {

    // MARK: - Test case types

    enum BundleSource: Sendable {
        /// Valid tarball written to disk.
        case validDiskTarball
        /// Valid bundle directory on disk.
        case validDiskDirectory
        /// File path that does not exist on disk.
        case missingDiskFile
        /// HTTP path the test server will serve with valid bundle data.
        case validHTTP(path: String)
        /// HTTP path not found on the test server (expects 404).
        case missingHTTP(path: String)
    }

    struct BundleEntry: Sendable {
        let name: String
        let source: BundleSource
    }

    struct TestCase: Sendable {
        let description: String
        let bundles: [BundleEntry]
        let expectedSuccessNames: Set<String>
        let expectedFailureNames: Set<String>
    }

    // MARK: - Test cases

    static var testCases: [TestCase] {
        [
            TestCase(
                description: "3 disk tarballs, all succeed",
                bundles: [
                    BundleEntry(name: "b1", source: .validDiskTarball),
                    BundleEntry(name: "b2", source: .validDiskTarball),
                    BundleEntry(name: "b3", source: .validDiskTarball),
                ],
                expectedSuccessNames: ["b1", "b2", "b3"],
                expectedFailureNames: []
            ),
            TestCase(
                description: "2 HTTP bundles, all succeed",
                bundles: [
                    BundleEntry(name: "h1", source: .validHTTP(path: "/bundles/h1")),
                    BundleEntry(name: "h2", source: .validHTTP(path: "/bundles/h2")),
                ],
                expectedSuccessNames: ["h1", "h2"],
                expectedFailureNames: []
            ),
            TestCase(
                description: "1 disk tarball + 1 disk directory, both succeed",
                bundles: [
                    BundleEntry(name: "tar-bundle", source: .validDiskTarball),
                    BundleEntry(name: "dir-bundle", source: .validDiskDirectory),
                ],
                expectedSuccessNames: ["tar-bundle", "dir-bundle"],
                expectedFailureNames: []
            ),
            TestCase(
                description: "1 valid disk tarball + 1 missing disk file, partial failure",
                bundles: [
                    BundleEntry(name: "good", source: .validDiskTarball),
                    BundleEntry(name: "missing", source: .missingDiskFile),
                ],
                expectedSuccessNames: ["good"],
                expectedFailureNames: ["missing"]
            ),
            TestCase(
                description: "1 valid HTTP + 1 unregistered HTTP path, partial failure",
                bundles: [
                    BundleEntry(name: "good", source: .validHTTP(path: "/bundles/good")),
                    BundleEntry(name: "bad", source: .missingHTTP(path: "/bundles/does-not-exist")),
                ],
                expectedSuccessNames: ["good"],
                expectedFailureNames: ["bad"]
            ),
            TestCase(
                description: "2 missing disk files, all fail",
                bundles: [
                    BundleEntry(name: "bad1", source: .missingDiskFile),
                    BundleEntry(name: "bad2", source: .missingDiskFile),
                ],
                expectedSuccessNames: [],
                expectedFailureNames: ["bad1", "bad2"]
            ),
            TestCase(
                description: "1 disk tarball + 1 HTTP bundle, mixed loaders both succeed",
                bundles: [
                    BundleEntry(name: "disk-bundle", source: .validDiskTarball),
                    BundleEntry(name: "http-bundle", source: .validHTTP(path: "/bundles/http-bundle")),
                ],
                expectedSuccessNames: ["disk-bundle", "http-bundle"],
                expectedFailureNames: []
            ),
            TestCase(
                description: "1 valid disk + 1 missing HTTP, mixed loaders partial failure",
                bundles: [
                    BundleEntry(name: "disk-ok", source: .validDiskTarball),
                    BundleEntry(name: "http-miss", source: .missingHTTP(path: "/bundles/not-here")),
                ],
                expectedSuccessNames: ["disk-ok"],
                expectedFailureNames: ["http-miss"]
            ),
        ]
    }

    // MARK: - Parameterised test

    @Test("Parallel bundle loading", arguments: testCases)
    func testParallelBundleLoading(_ tc: TestCase) async throws {
        let tempDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let testBundlesConfig = try generateBundleFromTestCase(tc.bundles, tempDir: tempDir)

        let server: TestBundleServer? =
            testBundlesConfig.needsHTTP
            ? try await TestBundleServer.start(files: testBundlesConfig.httpFiles) : nil
        defer {
            if let server { Task { try? await server.shutdown() } }
        }

        let rt = try await makeRuntime(
            configBundles: testBundlesConfig.configBundles,
            server: server
        )
        let runTask = Task { try await rt.run() }
        defer { runTask.cancel() }

        let totalExpected = tc.expectedSuccessNames.count + tc.expectedFailureNames.count
        try await waitForBundles(runtime: rt, expectedCount: totalExpected)

        try await assertBundleResults(
            runtime: rt,
            expectedSuccessNames: tc.expectedSuccessNames,
            expectedFailureNames: tc.expectedFailureNames
        )
    }

    // MARK: - Helpers

    /// Poll the runtime's bundle storage until it reaches the expected count or times out.
    private func waitForBundles(
        runtime: OPA.Runtime,
        expectedCount: Int,
        timeout: Duration = .seconds(10)
    ) async throws {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            let count = runtime.activeBundles().count
            if count >= expectedCount { return }
            try await Task.sleep(for: .milliseconds(100))
        }
    }

    /// Intermediate result of materialising bundle entries to disk / HTTP mappings.
    private struct TestBundlesConfig {
        var httpFiles: [String: Data] = [:]
        var configBundles: [(name: String, json: String)] = []
        var needsHTTP = false
    }

    /// Write bundles to disk and/or prepare HTTP file mappings for each entry.
    private func generateBundleFromTestCase(
        _ entries: [BundleEntry],
        tempDir: URL
    ) throws -> TestBundlesConfig {
        var result = TestBundlesConfig()

        for entry in entries {
            switch entry.source {
            case .validDiskTarball:
                let bundle = try makeExampleBundle()
                let path = tempDir.appendingPathComponent("\(entry.name).tar.gz")
                try OPA.Bundle.encodeToTarball(bundle: bundle).write(to: path)
                result.configBundles.append((entry.name, #"{"resource": "\#(path.absoluteString)"}"#))

            case .validDiskDirectory:
                let bundle = try makeExampleBundle()
                let dirPath = tempDir.appendingPathComponent(entry.name)
                try OPA.Bundle.encodeToDirectory(bundle: bundle, targetURL: dirPath)
                result.configBundles.append((entry.name, #"{"resource": "\#(dirPath.absoluteString)"}"#))

            case .missingDiskFile:
                let missingPath = tempDir.appendingPathComponent("\(entry.name)-nonexistent.tar.gz")
                result.configBundles.append((entry.name, #"{"resource": "\#(missingPath.absoluteString)"}"#))

            case .validHTTP(let path):
                result.needsHTTP = true
                let bundle = try makeExampleBundle()
                let data = try OPA.Bundle.encodeToTarball(bundle: bundle)
                result.httpFiles[path] = data
                result.configBundles.append((entry.name, #"{"service": "svc", "resource": "\#(path)"}"#))

            case .missingHTTP(let path):
                result.needsHTTP = true
                result.configBundles.append((entry.name, #"{"service": "svc", "resource": "\#(path)"}"#))
            }
        }

        return result
    }

    /// Build a config JSON string and decode it into an `OPA.Runtime`.
    private func makeRuntime(
        configBundles: [(name: String, json: String)],
        server: TestBundleServer?
    ) async throws -> OPA.Runtime {
        let bundlesJSON =
            configBundles
            .map { #""\#($0.name)": \#($0.json)"# }
            .joined(separator: ",\n        ")
        let servicesJSON: String =
            server.map {
                #""services": {"svc": {"url": "\#($0.baseURL)"}},"#
            } ?? ""

        let configJSON = """
            {
              \(servicesJSON)
              "bundles": {
                \(bundlesJSON)
              }
            }
            """

        let config = try JSONDecoder().decode(
            OPA.Config.self, from: configJSON.data(using: .utf8)!)
        return try OPA.Runtime(config: config)
    }

    // Assert that bundle storage and the computed `bundles` property match expectations.
    private func assertBundleResults(
        runtime rt: OPA.Runtime,
        expectedSuccessNames: Set<String>,
        expectedFailureNames: Set<String>
    ) async throws {
        let totalExpected = expectedSuccessNames.count + expectedFailureNames.count
        let statuses = rt.activeBundles()

        #expect(
            statuses.count == totalExpected,
            "Expected \(totalExpected) bundle result(s), got \(statuses.count)")

        for name in expectedSuccessNames {
            if let status = statuses[name] {
                if status.bundle == nil {
                    Issue.record("Expected bundle '\(name)' to succeed, got \(status)")
                }
            } else {
                Issue.record("Expected '\(name)' key in activeBundles")
            }
        }

        for name in expectedFailureNames {
            if let status = statuses[name] {
                if status.bundle != nil {
                    Issue.record("Expected bundle '\(name)' to fail, got \(status)")
                }
            } else {
                Issue.record("Expected '\(name)' key in activeBundles")
            }
        }

        let successBundles = rt.bundles
        #expect(
            successBundles.count == expectedSuccessNames.count,
            "Expected \(expectedSuccessNames.count) successful bundle(s), got \(successBundles.count)")

        for name in expectedSuccessNames {
            #expect(successBundles[name] != nil, "Expected '\(name)' in successful bundles")
        }
        for name in expectedFailureNames {
            #expect(successBundles[name] == nil, "Expected '\(name)' NOT in successful bundles")
        }
    }
}

// MARK: - CustomTestStringConvertible

extension ParallelBundleLoadingTests.TestCase: CustomTestStringConvertible {
    var testDescription: String { description }
}
