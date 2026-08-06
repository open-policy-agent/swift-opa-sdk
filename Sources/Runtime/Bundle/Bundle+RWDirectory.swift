import AST
import Foundation
import Rego
import SWCompression

extension OPA.Bundle {
    /// Builds an ``OPA.Bundle`` from a directory.
    public static func decodeFromDirectory(fromDir: URL) throws -> OPA.Bundle {
        guard let isDir = try fromDir.resourceValues(forKeys: [.isDirectoryKey]).isDirectory, isDir else {
            throw OPA.Bundle.LoadError.unsupported("URL was not a directory path")
        }

        guard !(try FileManager.default.contentsOfDirectory(atPath: fromDir.path).isEmpty) else {
            throw OPA.Bundle.LoadError.unsupported("Directory was empty")
        }

        var regoFiles: [BundleFile] = []
        var planFiles: [BundleFile] = []
        var manifest: OPA.Manifest?
        var data: AST.RegoValue = AST.RegoValue.object([:])

        // We create an emumerator that filters for only files/folders.
        guard
            let enumerator = FileManager.default.enumerator(
                at: fromDir,
                includingPropertiesForKeys: [.nameKey, .isDirectoryKey, .isRegularFileKey],
                options: [],
                errorHandler: { url, error in
                    print("Error accessing \(url.path): \(error.localizedDescription)")
                    return true
                }
            )
        else {
            throw OPA.Bundle.LoadError.unsupported("Could not create file enumerator for \(fromDir.path)")
        }

        // Walk the directory tree recursively, filtering for file types we care about.
        // File contents are lazily loaded.
        for case let fileURL as URL in enumerator {
            // Skip directories, only process files.
            guard
                let resourceValues = try? fileURL.resourceValues(forKeys: [.isRegularFileKey]),
                resourceValues.isRegularFile == true
            else { continue }

            // Get the relative path from the root directory as a string
            let relativePath = getRelativePath(from: fromDir, to: fileURL)

            // Format the path to match Go's Chrooted format
            let bundlePath = formatBundlePath(relativePath)
            // Reject paths that would escape the bundle root.
            try validateBundlePathWithinRoot(bundlePath)
            guard let bundlePathURL = URL(string: bundlePath) else {
                throw OPA.Bundle.LoadError.unsupported("Could not create bundle path URL for \(bundlePath)")
            }
            switch bundlePath {
            case "/.manifest":
                guard manifest == nil else {
                    // Only allow a single manifest in the bundle.
                    throw OPA.Bundle.LoadError.unexpectedManifest(bundlePathURL)
                }
                do {
                    manifest = try OPA.Manifest(from: Data(contentsOf: fileURL))
                } catch {
                    throw OPA.Bundle.LoadError.dataParseError(bundlePathURL, error)
                }

            case let x where x.hasSuffix(".rego"):
                regoFiles.append(
                    BundleFile(url: bundlePathURL, data: try Data(contentsOf: fileURL)))

            case let x where x.hasSuffix("plan.json"):
                planFiles.append(
                    BundleFile(url: bundlePathURL, data: try Data(contentsOf: fileURL)))

            case let x where x.hasSuffix("data.json"):
                // Parse JSON into AST values
                var parsed: AST.RegoValue
                do {
                    parsed = try AST.RegoValue(jsonData: Data(contentsOf: fileURL))
                } catch {
                    throw OPA.Bundle.LoadError.dataParseError(bundlePathURL, error)
                }

                // Determine the relative path and patch the data into the data tree
                let relPath = x.split(separator: "/").dropLast().map { String($0) }
                data = data.patch(with: parsed, at: relPath)

            case let x where x.hasSuffix("data.yaml") || x.hasSuffix("data.yml"):
                // Parse YAML into AST values
                var parsed: AST.RegoValue
                do {
                    parsed = try AST.RegoValue(yamlData: Data(contentsOf: fileURL))
                } catch {
                    throw OPA.Bundle.LoadError.dataParseError(bundlePathURL, error)
                }

                // Determine the relative path and patch the data into the data tree
                let relPath = x.split(separator: "/").dropLast().map { String($0) }
                data = data.patch(with: parsed, at: relPath)

            // Skip all other cases.
            default:
                break
            }
        }

        regoFiles.sort(by: { $0.url.path < $1.url.path })
        planFiles.sort(by: { $0.url.path < $1.url.path })

        manifest = manifest ?? OPA.Manifest()  // Default manifest if none was provided
        let bundle = try OPA.Bundle(manifest: manifest!, planFiles: planFiles, regoFiles: regoFiles, data: data)

        // Validate the data paths are all under the declared roots
        // TODO

        return bundle
    }

    /// Writes the contents of an OPA.Bundle to disk as a folder hierarchy.
    /// This will create any intermediate directories in the target URL if they don't already exist.
    public static func encodeToDirectory(bundle: OPA.Bundle, targetURL: URL) throws {
        try FileManager.default.createDirectory(
            at: targetURL,
            withIntermediateDirectories: true,
            attributes: nil
        )

        // Write the manifest and data.json files out.
        let manifestData = try JSONEncoder().encode(bundle.manifest)
        try manifestData.write(to: targetURL.appendingPathComponent(".manifest", isDirectory: false), options: .atomic)

        let dataJSON: Data = try JSONEncoder().encode(bundle.data)
        try dataJSON.write(to: targetURL.appendingPathComponent("data.json", isDirectory: false), options: .atomic)

        // Write all bundle files out.
        for file in bundle.planFiles + bundle.regoFiles {
            // Get the path string from URL and remove leading "/" for filesystem operations
            var relativePath = file.url.path
            if relativePath.hasPrefix("/") {
                relativePath = String(relativePath.dropFirst())
            }

            // Build the full destination URL by appending the relative path
            let destinationURL = targetURL.appendingPathComponent(relativePath, isDirectory: false)

            // Guard against path traversal: ensure the resolved destination stays
            // within targetURL before creating any directories or writing. This
            // protects bundles built in-memory or loaded from any source, not just
            // tarballs, and runs before createDirectory so an escaping entry can't
            // create parent directories outside the target.
            let base = targetURL.standardizedFileURL
            let dest = destinationURL.standardizedFileURL
            guard dest.path == base.path || dest.path.hasPrefix(base.path + "/") else {
                throw OPA.Bundle.LoadError.unsafeBundlePath(file.url.path)
            }

            // Derive the parent directory and create it (+ any intermediates) if needed
            let directoryURL = destinationURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true,
                attributes: nil
            )

            // Write the file contents to disk
            try file.data.write(to: destinationURL, options: .atomic)
        }
    }
}

// Helper to get the relative path as a string (matching Go's behavior)
private func getRelativePath(from base: URL, to child: URL) -> String {
    // Resolve symlinks before comparing paths
    let canonicalBase = base.resolvingSymlinksInPath().standardizedFileURL
    let canonicalChild = child.resolvingSymlinksInPath().standardizedFileURL

    let baseComponents = canonicalBase.pathComponents
    let childComponents = canonicalChild.pathComponents

    if !childComponents.starts(with: baseComponents) {
        // This shouldn't happen with FileManager enumeration, but handle it
        return canonicalChild.path
    }

    let relativeComponents = childComponents.dropFirst(baseComponents.count)
    return relativeComponents.joined(separator: "/")
}

// Format path to match Go's Chrooted format behavior
// Returns a string path suitable for creating a URL with URL(string:)
private func formatBundlePath(_ path: String) -> String {
    // Ensure leading "/" for all other paths
    if !path.hasPrefix("/") {
        return "/" + path
    }
    return path
}

/// Verifies that a bundle-relative path does not escape the bundle root via
/// `..` traversal, throwing ``OPA/Bundle/LoadError/unsafeBundlePath(_:)`` if it does.
///
/// We reject any path that normalizes to a location above its root.
///
/// The check is lexical (no filesystem or symlink resolution) so it
/// cannot be fooled by a partially-written directory tree.
///
/// - Parameter path: A path that has already been through ``formatBundlePath(_:)``
///   (has a leading `/`).
func validateBundlePathWithinRoot(_ path: String) throws {
    var depth = 0
    for segment in path.split(separator: "/", omittingEmptySubsequences: true) {
        switch segment {
        case ".":
            continue
        case "..":
            depth -= 1
            if depth < 0 {
                throw OPA.Bundle.LoadError.unsafeBundlePath(path)
            }
        default:
            depth += 1
        }
    }
}
