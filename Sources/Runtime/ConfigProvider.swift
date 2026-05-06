import Config
import Foundation
import Logging
import Rego

extension OPA {
    /// A type that produces configuration updates over time.
    ///
    /// Implementations run independently (off the Runtime actor), and
    /// like BundleLoaders, are periodically polled for config changes
    /// using the `load` method. The Runtime consumes these updates, and
    /// reloads bundles and restarts the bundle fetching workers after
    /// loading each successful new configuration.
    ///
    /// If an error result is returned, the Runtime will keep the existing
    /// configuration and bundle fetching workers until a new configuration
    /// is successfully fetched and applied.
    ///
    /// Conforming types must be `Sendable` so they can be safely handed
    /// off to a child task in the Runtime's task group.
    public protocol ConfigProvider: Sendable {
        /// Needs a public constructor that can build from the config directly.
        init(config: OPA.Config, logger: Logger?) throws

        /// Load (or re-load) the discovered configuration, based on the
        /// initial config and any existing state.
        mutating func load() async -> Result<OPA.Config, any Swift.Error>
    }

    /// HTTPConfigProvider is a slightly more specialized protocol to allow greater
    /// control for HTTP-based config providers (e.g. Discovery).
    public protocol HTTPConfigProvider: ConfigProvider, Sendable {
        /// Used by the loader-managing task to determine whether to sleep or not between polls.
        func isLongPollingEnabled() -> Bool
    }
}
