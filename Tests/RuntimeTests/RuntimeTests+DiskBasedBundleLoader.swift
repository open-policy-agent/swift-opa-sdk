import Foundation
import Rego
import Testing

@testable import Runtime

// MARK: - Runtime Tests

@Suite("RuntimeDiskBasedBundleTests")
struct RuntimeDiskBasedBundleTests {

    struct TestCase: Sendable {
        let description: String
        let config: String
        let useDirectory: Bool
        let bundleName: String

        init(description: String, config: String, useDirectory: Bool, bundleName: String? = nil) {
            self.description = description
            self.config = config
            self.useDirectory = useDirectory
            self.bundleName = bundleName ?? (useDirectory ? "bundle-dir" : "bundle.tar.gz")
        }
    }

    static var validTestCases: [TestCase] {
        return [
            TestCase(
                description: "simple file url (tarball)",
                config: #"""
                    {
                      "bundles" : {
                        "test": {"resource": "file:///{TEMP}/bundle.tar.gz"}
                      }
                    }
                    """#,
                useDirectory: false,
                bundleName: "bundle.tar.gz"
            ),
            TestCase(
                description: "simple file url (directory)",
                config: #"""
                    {
                      "bundles" : {
                        "test": {"resource": "file:///{TEMP}/bundle-dir"}
                      }
                    }
                    """#,
                useDirectory: true,
                bundleName: "bundle-dir"
            ),
            TestCase(
                description: "file url with spaces in path (tarball)",
                config: #"""
                    {
                      "bundles" : {
                        "test": {"resource": "file:///{TEMP}/path%20with%20spaces/bundle.tar.gz"}
                      }
                    }
                    """#,
                useDirectory: false,
                bundleName: "path with spaces/bundle.tar.gz"
            ),
            TestCase(
                description: "file url with spaces in path (directory)",
                config: #"""
                    {
                      "bundles" : {
                        "test": {"resource": "file:///{TEMP}/path%20with%20spaces/bundle-dir"}
                      }
                    }
                    """#,
                useDirectory: true,
                bundleName: "path with spaces/bundle-dir"
            ),
        ]
    }

    @Test(arguments: validTestCases)
    func testValid(tc: TestCase) async throws {
        let tempDir = try makeTempDir()
        defer {
            try? FileManager.default.removeItem(at: tempDir)
        }
        let testBundle = try makeExampleBundle()
        let bundleURL = tempDir.appendingPathComponent(tc.bundleName)
        if tc.useDirectory {
            try OPA.Bundle.encodeToDirectory(bundle: testBundle, targetURL: bundleURL)
        } else {
            // We have to create the intermediate parent directories for the tarball case,
            // or we'll get an exciting NSError about the file not existing.
            let bundleURL = tempDir.appendingPathComponent(tc.bundleName)
            try FileManager.default.createDirectory(
                at: bundleURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try OPA.Bundle.encodeToTarball(bundle: testBundle).write(to: bundleURL)
        }

        // Build an updated OPA Config, then start up the runtime.
        let updatedConfig: Data = tc.config.replacingOccurrences(of: "{TEMP}", with: tempDir.path()).data(using: .utf8)!
        let config: OPA.Config = try JSONDecoder().decode(OPA.Config.self, from: updatedConfig)
        let rt = try OPA.Runtime(config: config)

        let backgroundFetchTask = Task { try await rt.run() }
        defer { backgroundFetchTask.cancel() }
        let _ = await waitForBundleLoad(rt: rt, name: "test", timeout: .seconds(1))

        let bundleStorage = rt.activeBundles()
        #expect(bundleStorage.count == 1, "Expected exactly 1 succesful bundle load, got \(bundleStorage.count)")
        #expect(bundleStorage.allSatisfy { $0.value.bundle != nil })

        // Check decision result.
        let dr = try await rt.decision("data/foo/hello", input: nil)
        #expect(dr.result.first == ["result": 1])
    }

    struct InvalidTestCase: Sendable {
        let description: String
        let config: String
        /// If true, we need a temp dir substituted into the config
        let needsTempDir: Bool
        /// At which stage should this fail?
        let failsAt: FailureStage

        enum FailureStage: Sendable {
            case decode  // JSONDecoder fails
            case loadFails  // the source is invalid/missing, so the bundle never activates
        }
    }

    static var invalidTestCases: [InvalidTestCase] {
        return [
            // Empty/missing resource — URL(string: "") yields a non-file URL
            InvalidTestCase(
                description: "missing resource field",
                config: #"""
                        {
                            "bundles": {
                                "test": {}
                            }
                        }
                    """#,
                needsTempDir: false,
                failsAt: .decode
            ),
            // Non-file scheme with no matching service configured
            InvalidTestCase(
                description: "https scheme without service config",
                config: #"""
                        {
                            "bundles": {
                                "test": {"resource": "https://example.com/bundle.tar.gz"}
                            }
                        }
                    """#,
                needsTempDir: false,
                failsAt: .decode
            ),
            // References a service name that doesn't exist in "services"
            InvalidTestCase(
                description: "references nonexistent service",
                config: #"""
                        {
                            "bundles": {
                                "test": {"service": "ghost", "resource": "/bundle.tar.gz"}
                            }
                        }
                    """#,
                needsTempDir: false,
                failsAt: .decode
            ),
            // Valid file:// URL, but nothing exists at the path
            InvalidTestCase(
                description: "nonexistent bundle path (tarball)",
                config: #"""
                        {
                            "bundles": {
                                "test": {"resource": "file:///no/such/path/bundle.tar.gz"}
                            }
                        }
                    """#,
                needsTempDir: false,
                failsAt: .loadFails
            ),
            // Points at a file:// directory that exists but is empty (no manifest, no data)
            InvalidTestCase(
                description: "empty bundle directory",
                config: #"""
                        {
                            "bundles": {
                                "test": {"resource": "file:///{TEMP}/empty-bundle"}
                            }
                        }
                    """#,
                needsTempDir: true,
                failsAt: .loadFails
            ),
            // Malformed JSON where bundles value is wrong type
            InvalidTestCase(
                description: "bundles config is not an object",
                config: #"""
                        {
                            "bundles": "not-an-object"
                        }
                    """#,
                needsTempDir: false,
                failsAt: .decode
            ),
        ]
    }

    @Test(arguments: invalidTestCases)
    func testInvalid(tc: InvalidTestCase) async throws {
        var configString = tc.config
        var tempDir: URL? = nil

        if tc.needsTempDir {
            tempDir = try makeTempDir()
            configString = configString.replacingOccurrences(of: "{TEMP}", with: tempDir!.path())

            // Create an empty directory for the "empty bundle" case
            let emptyDir = tempDir!.appendingPathComponent("empty-bundle")
            try FileManager.default.createDirectory(at: emptyDir, withIntermediateDirectories: true)
        }

        defer {
            if let tempDir { try? FileManager.default.removeItem(at: tempDir) }
        }

        switch tc.failsAt {
        case .decode:
            #expect(throws: (any Error).self) {
                _ = try JSONDecoder().decode(OPA.Config.self, from: configString.data(using: .utf8)!)
            }

        case .loadFails:
            let config = try JSONDecoder().decode(OPA.Config.self, from: configString.data(using: .utf8)!)
            let rt = try OPA.Runtime(config: config)

            let backgroundFetchTask = Task { try await rt.run() }
            defer { backgroundFetchTask.cancel() }

            // The source is invalid/missing, so every poll fails: the bundle is
            // never activated and an error is recorded in its status metadata.
            let meta = await waitForBundleError(rt: rt, name: "test", timeout: .seconds(2))
            #expect(meta?.code != nil, "expected a load error to be recorded")
            #expect(
                rt.activeBundles()["test"]?.bundle == nil,
                "an invalid source must not activate a bundle")
        }
    }
}

// MARK: - Type Extensions

extension RuntimeDiskBasedBundleTests.TestCase: CustomTestStringConvertible {
    var testDescription: String { description }
}

extension RuntimeDiskBasedBundleTests.InvalidTestCase: CustomTestStringConvertible {
    var testDescription: String { description }
}
