import AST
import Foundation
import Rego
import SWCompression

extension OPA.Bundle {
    /// Builds a tar archive (.tar) from an ``OPA.Bundle``.
    public static func encodeToTarArchive(bundle: OPA.Bundle) throws -> Data {
        var entries: [TarEntry] = []
        entries.reserveCapacity(2 + bundle.planFiles.count + bundle.regoFiles.count)

        // Add entry for .manifest
        let manifestData = try JSONEncoder().encode(bundle.manifest)
        entries.append(TarEntry(info: TarEntryInfo(name: ".manifest", type: .regular), data: manifestData))

        // Add entry for data.json
        let dataJSON = try JSONEncoder().encode(bundle.data)
        entries.append(TarEntry(info: TarEntryInfo(name: "data.json", type: .regular), data: dataJSON))

        // Add one entry per file.
        for file in bundle.planFiles {
            entries.append(TarEntry(info: TarEntryInfo(name: file.url.path(), type: .regular), data: file.data))
        }

        for file in bundle.regoFiles {
            entries.append(TarEntry(info: TarEntryInfo(name: file.url.path(), type: .regular), data: file.data))
        }

        return TarContainer.create(from: entries)
    }

    /// Builds a tarball (.tar.gz) from an ``OPA.Bundle``.
    public static func encodeToTarball(bundle: OPA.Bundle) throws -> Data {
        let tarData = try encodeToTarArchive(bundle: bundle)
        return try GzipArchive.archive(data: tarData)
    }

    /// Builds an ``OPA.Bundle`` from a tar archive (.tar).
    public static func decodeFromTarArchive(from: Data) throws -> OPA.Bundle {
        let tarEntries: [TarEntry] = try TarContainer.open(container: from)

        var regoFiles: [BundleFile] = []
        var planFiles: [BundleFile] = []
        var manifest: OPA.Manifest?
        var data: AST.RegoValue = AST.RegoValue.object([:])

        // Iterate across tar entries, and extract only the files we care about.
        for te in tarEntries {
            // Skip all directory entries and "special" file types like FIFOs that we don't care about.
            guard te.info.type == .regular else { continue }

            let bundlePath = formatBundlePath(te.info.name)
            // Reject entries whose path escapes the bundle root (e.g. "../escaped.rego").
            try validateBundlePathWithinRoot(bundlePath)
            guard let bundlePathURL = URL(string: bundlePath) else {
                throw OPA.Bundle.LoadError.unsupported("Could not create bundle path URL for \(bundlePath)")
            }
            switch bundlePath {
            case "/.manifest":
                guard manifest == nil else {
                    // Only allow a single manifest in the bundle
                    throw OPA.Bundle.LoadError.unexpectedManifest(bundlePathURL)
                }

                guard let entryData = te.data else {
                    throw OPA.Bundle.LoadError.manifestParseError(
                        bundlePathURL,
                        NSError(
                            domain: "TarballLoader", code: 1,
                            userInfo: [
                                NSLocalizedDescriptionKey: "Empty manifest at \(bundlePathURL)"
                            ]))
                }

                do {
                    manifest = try OPA.Manifest(from: entryData)
                } catch {
                    throw OPA.Bundle.LoadError.manifestParseError(bundlePathURL, error)
                }
            case let x where x.hasSuffix(".rego"):
                if let d: Data = te.data {
                    regoFiles.append(BundleFile(url: bundlePathURL, data: d))
                }
            case let x where x.hasSuffix("plan.json"):
                if let d: Data = te.data {
                    planFiles.append(BundleFile(url: bundlePathURL, data: d))
                }
            case let x where x.hasSuffix("data.json"):
                guard let entryData = te.data else {
                    throw OPA.Bundle.LoadError.dataParseError(
                        bundlePathURL,
                        NSError(
                            domain: "TarballLoader", code: 1,
                            userInfo: [
                                NSLocalizedDescriptionKey: "Empty data json file at \(bundlePathURL)"
                            ]))
                }

                // Parse JSON into AST values
                var parsed: AST.RegoValue
                do {
                    parsed = try AST.RegoValue(jsonData: entryData)
                } catch {
                    throw OPA.Bundle.LoadError.dataParseError(bundlePathURL, error)
                }

                // Determine the relative path and patch the data into the data tree
                let relPath = x.split(separator: "/").dropLast().map { String($0) }
                data = data.patch(with: parsed, at: relPath)

            case let x where x.hasSuffix("data.yaml") || x.hasSuffix("data.yml"):
                guard let entryData = te.data else {
                    throw OPA.Bundle.LoadError.dataParseError(
                        bundlePathURL,
                        NSError(
                            domain: "TarballLoader", code: 1,
                            userInfo: [
                                NSLocalizedDescriptionKey: "Empty data yaml file at \(bundlePathURL)"
                            ]))
                }

                // Parse YAML into AST values
                var parsed: AST.RegoValue
                do {
                    parsed = try AST.RegoValue(yamlData: entryData)
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

    /// Builds an ``OPA.Bundle`` from a tarball (.tar.gz) file.
    public static func decodeFromTarball(from: Data) throws -> OPA.Bundle {
        let decompressedTarball = try GzipArchive.unarchive(archive: from)
        return try decodeFromTarArchive(from: decompressedTarball)
    }

    public enum LoadError: Swift.Error {
        case unexpectedManifest(URL)
        case unexpectedData(URL)
        case manifestParseError(URL, Swift.Error)
        case dataParseError(URL, Swift.Error)
        case dataEscapedRoot
        /// A bundle file path escaped the bundle root (path traversal, e.g. "../escaped.rego").
        case unsafeBundlePath(String)
        case unsupported(String)
    }
}

private func formatBundlePath(_ path: String) -> String {
    if !path.hasPrefix("/") {
        return "/" + path
    }
    return path
}
