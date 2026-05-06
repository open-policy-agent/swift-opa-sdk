import Config
import Foundation
import Logging
import Rego
import Runtime

// MARK: - Mock Bundle Loader Registry

/// Process-wide registry for scripted ``MockBundleLoader`` behavior.
///
/// Each test registers a script under a unique ID (typically a UUID) and
/// embeds that ID in the OPA config under `plugins.mock_loader.id`. When
/// `MockBundleLoader.init(discoveryConfig:)` runs as part of the standard
/// loader-discovery flow inside ``OPA/DiscoveryConfigProvider``, it reads
/// the ID from the config and binds itself to the corresponding script
/// slot in this registry.
///
/// Concurrent tests are safe so long as their IDs are unique: each test
/// touches only its own slot, and the registry's `NSLock` serializes
/// access to the dictionary itself.
final class MockBundleLoaderRegistry: @unchecked Sendable {
    static let shared = MockBundleLoaderRegistry()

    /// Per-ID scripted state.
    final class Slot {
        var scripted: [Result<OPA.Bundle, any Error>]
        var index: Int = 0
        init(scripted: [Result<OPA.Bundle, any Error>]) {
            self.scripted = scripted
        }
    }

    private let lock = NSLock()
    private var slots: [String: Slot] = [:]

    private init() {}

    /// Register a script under a fresh ID and return that ID.
    func register(scripted: [Result<OPA.Bundle, any Error>]) -> String {
        let id = UUID().uuidString
        lock.withLock {
            slots[id] = Slot(scripted: scripted)
        }
        return id
    }

    /// Remove an ID's slot. Tests should call this in a `defer`.
    func unregister(id: String) {
        lock.withLock {
            _ = slots.removeValue(forKey: id)
        }
    }

    /// Pop the next scripted result for `id`. After the script is exhausted,
    /// repeats the last result indefinitely so the provider's polling loop
    /// continues until the test cancels it.
    func nextResult(for id: String) -> Result<OPA.Bundle, any Error> {
        lock.withLock {
            guard let slot = slots[id] else {
                return .failure(
                    RuntimeError(
                        code: .internalError,
                        message: "MockBundleLoader: no script registered for id \(id)"
                    ))
            }
            if slot.index < slot.scripted.count {
                let r = slot.scripted[slot.index]
                slot.index += 1
                return r
            }
            return slot.scripted.last
                ?? .failure(
                    RuntimeError(
                        code: .internalError,
                        message: "MockBundleLoader: empty script for id \(id)"
                    ))
        }
    }
}

// MARK: - Mock Bundle Loader

extension OPA {
    /// A ``OPA/BundleLoader`` implementation that returns scripted results.
    ///
    /// Reads its ID from `config.plugins["mock_loader"].id` and looks up its
    /// per-call script in ``MockBundleLoaderRegistry``. This lets tests use
    /// the standard public ``OPA/DiscoveryConfigProvider`` init flow while
    /// still injecting deterministic load behavior.
    struct MockBundleLoader: OPA.BundleLoader {
        let id: String

        init(config: OPA.Config, bundleResourceName: String, logger: Logger? = nil) throws {
            self.id = try Self.extractID(from: config)
        }

        init(discoveryConfig config: OPA.Config, logger: Logger? = nil) throws {
            self.id = try Self.extractID(from: config)
        }

        func load() async -> Result<OPA.Bundle, any Error> {
            MockBundleLoaderRegistry.shared.nextResult(for: id)
        }

        static func compatibleWithConfig(config: OPA.Config, bundleResourceName: String) -> Bool {
            (try? extractID(from: config)) != nil
        }

        static func compatibleWithDiscoveryConfig(config: OPA.Config) -> Bool {
            (try? extractID(from: config)) != nil
        }

        /// Pulls `plugins.mock_loader.id` out of the config.
        private static func extractID(from config: OPA.Config) throws -> String {
            guard
                let plugins = config.plugins,
                let entry = plugins["mock_loader"]
            else {
                throw RuntimeError(
                    code: .internalError,
                    message: "MockBundleLoader: no plugins.mock_loader section in config"
                )
            }

            // entry is AnyCodable; reach into its .value as [String: Any].
            guard
                let dict = entry.value as? [String: Any],
                let id = dict["id"] as? String
            else {
                throw RuntimeError(
                    code: .internalError,
                    message: "MockBundleLoader: plugins.mock_loader.id missing or not a string"
                )
            }
            return id
        }
    }
}
