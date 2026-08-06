import Foundation
import Rego
import SWCompression
import Testing

@testable import Runtime

// MARK: - Bundle path-traversal tests
//
// Bundle files are written out to a target directory by `encodeToDirectory`.
// A malicious bundle (e.g. a tarball with an entry named `../escaped.rego`)
// must never escape its root, at decode time or at write time.

@Suite("BundlePathTraversalTests")
struct BundlePathTraversalTests {
    /// Build a gzipped tar containing a single regular entry with the given name.
    private func makeMaliciousTarball(entryName: String) throws -> Data {
        let entries = [
            TarEntry(
                info: TarEntryInfo(name: entryName, type: .regular),
                data: "package escaped\n\nx = 1".data(using: .utf8)!
            )
        ]
        let tar = TarContainer.create(from: entries)
        return try GzipArchive.archive(data: tar)
    }

    private func expectUnsafeBundlePath(
        _ body: () throws -> Void,
        _ context: String,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        do {
            try body()
            Issue.record(
                "expected \(context) to throw .unsafeBundlePath, but it succeeded", sourceLocation: sourceLocation)
        } catch let error as OPA.Bundle.LoadError {
            guard case .unsafeBundlePath = error else {
                Issue.record(
                    "expected \(context) to throw .unsafeBundlePath, got \(error)", sourceLocation: sourceLocation)
                return
            }
        } catch {
            Issue.record("expected \(context) to throw .unsafeBundlePath, got \(error)", sourceLocation: sourceLocation)
        }
    }

    @Test(
        "Decoding a tarball with a traversal entry is rejected",
        arguments: [
            "../escaped.rego",
            "../../etc/evil.rego",
            "foo/../../bar.rego",
        ]
    )
    func testDecodeRejectsTraversalEntry(entryName: String) throws {
        let tarball = try makeMaliciousTarball(entryName: entryName)
        expectUnsafeBundlePath(
            { _ = try OPA.Bundle.decodeFromTarball(from: tarball) },
            "decodeFromTarball(\(entryName))"
        )
    }

    @Test("encodeToDirectory rejects a traversal path and writes nothing outside the target")
    func testEncodeRejectsTraversalAndWritesNothingOutside() throws {
        let tempDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let targetURL = tempDir.appendingPathComponent("bundle-out", isDirectory: true)

        // A bundle whose rego file path escapes the target directory.
        let bundle = try OPA.Bundle(
            manifest: OPA.Manifest(roots: [""]),
            regoFiles: [
                Rego.BundleFile(
                    url: URL(string: "/../escaped.rego")!,
                    data: "package escaped\n\nx = 1".data(using: .utf8)!
                )
            ]
        )

        expectUnsafeBundlePath(
            { try OPA.Bundle.encodeToDirectory(bundle: bundle, targetURL: targetURL) },
            "encodeToDirectory(../escaped.rego)"
        )

        // The escaping file resolves to <tempDir>/escaped.rego (sibling of the
        // target). It must not have been written.
        let escapedURL = tempDir.appendingPathComponent("escaped.rego", isDirectory: false)
        #expect(
            !FileManager.default.fileExists(atPath: escapedURL.path),
            "path traversal wrote a file outside the target directory: \(escapedURL.path)"
        )
    }

    @Test("Round-trip through a tarball with normal nested paths still succeeds")
    func testBenignTarballRoundTrips() throws {
        let expectedBundle = try makeExampleBundle()
        let tarball = try OPA.Bundle.encodeToTarball(bundle: expectedBundle)
        let actualBundle = try OPA.Bundle.decodeFromTarball(from: tarball)
        #expect(expectedBundle == actualBundle)
    }
}
