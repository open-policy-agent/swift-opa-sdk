import Config
import Foundation
import Logging
import Rego

extension OPA {
    /// DiskBasedBundleLoader abstracts over loading bundles
    /// from on-disk folders and tarball files.
    ///
    /// `file://` URL paths are assumed to be absolute paths
    /// from the filesystem root, as per the RFC 8089 spec.
    /// (See: https://datatracker.ietf.org/doc/rfc8089/)
    ///
    /// ## Limitations
    ///
    /// - Bundle signature verification is not yet implemented.
    public struct DiskBasedBundleLoader: BundleLoader {
        /// The `bundle` resource name from the config.
        public let name: String

        /// The file URL of the folder or tarball on disk.
        public let fetchURL: URL

        /// Polling configuration.
        public let polling: PollingConfig?

        private var logger: Logger

        public init(config: OPA.Config, bundleResourceName: String, logger: Logger? = nil) throws {
            self.name = bundleResourceName
            guard let resource = config.bundles[bundleResourceName] else {
                throw RuntimeError(
                    code: .internalError,
                    message: "No bundle config was found for bundle resource \(bundleResourceName)."
                )
            }

            guard let url = URL(string: resource.resource ?? "") else {
                throw RuntimeError(
                    code: .internalError,
                    message: "Invalid URL for bundle config \(name): \(resource.resource ?? "")"
                )
            }

            // If no bundle service specified to fetch from, make sure we have a file URL to load from disk.
            guard !(resource.service.isEmpty && url.scheme != "file") else {
                throw RuntimeError(
                    code: .internalError,
                    message: "No service config or file:// URL was provided for bundle config \(name)."
                )
            }

            self.polling = resource.downloaderConfig.polling
            self.fetchURL = url
            self.logger = logger ?? Logger(label: "swift-opa.bundle.disk")
        }

        /// Constructor for loading from the `discovery` section of the config.
        public init(discoveryConfig config: OPA.Config, logger: Logger? = nil) throws {
            guard let discovery = config.discovery else {
                throw RuntimeError(
                    code: .internalError,
                    message: "No discovery config found."
                )
            }

            guard let url = URL(string: discovery.resource) else {
                throw RuntimeError(
                    code: .internalError,
                    message: "Invalid URL for discovery resource: \(discovery.resource)"
                )
            }

            guard url.scheme == "file" else {
                throw RuntimeError(
                    code: .internalError,
                    message: "DiskBasedBundleLoader requires a file:// URL for discovery resource."
                )
            }

            self.name = "discovery"
            self.fetchURL = url
            self.polling = discovery.downloaderConfig.polling
            self.logger = Logger(label: "swift-opa.bundle.disk.discovery")
        }

        /// Compatibility check against the OPA bundle config section.
        /// This check only returns `true` if the `url` field is a `file://` URL.
        public static func compatibleWithConfig(config: OPA.Config, bundleResourceName: String) -> Bool {
            guard let resource = config.bundles[bundleResourceName] else {
                return false
            }

            return (URL(string: resource.resource ?? "")?.scheme == "file")
        }

        /// Compatibility check against the OPA discovery config section.
        /// This check only returns `true` if the `url` field is a `file://` URL.
        public static func compatibleWithDiscoveryConfig(config: OPA.Config) -> Bool {
            guard let discovery = config.discovery else {
                return false
            }
            return URL(string: discovery.resource)?.scheme == "file"
        }

        /// Loads a bundle from disk, returning either a successfully parsed
        /// OPA bundle, or an error.
        public func load() async -> Result<Bundle, any Swift.Error> {
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: self.fetchURL.path, isDirectory: &isDirectory) {
                if isDirectory.boolValue {
                    // Assert directory not empty before attempting to load it as a bundle.
                    do {
                        guard !(try FileManager.default.contentsOfDirectory(atPath: self.fetchURL.path).isEmpty)
                        else {
                            throw OPA.Bundle.LoadError.unsupported("Directory was empty")
                        }
                    } catch {
                        return .failure(
                            RuntimeError(
                                code: .internalError,
                                message:
                                    "bundle \(name) failed to load with error: \(error)"
                            ))
                    }
                    // Directory not empty.
                    do {
                        let bundle = try Bundle.decodeFromDirectory(fromDir: self.fetchURL)
                        return .success(bundle)
                    } catch {
                        return .failure(error)
                    }
                } else {
                    do {
                        let bundleData = try Data(contentsOf: self.fetchURL)
                        let bundle = try Bundle.decodeFromTarball(from: bundleData)
                        return .success(bundle)
                    } catch {
                        return .failure(error)
                    }
                }
            }
            return .failure(
                RuntimeError(
                    code: .internalError,
                    message:
                        "bundle \(name) failed to load. No file or directory found."
                ))
        }
    }
}
