import AST
import AsyncHTTPClient
import Config
import Foundation
import IR
import Logging
import Rego

extension OPA {
    /// A ``ConfigProvider`` that implements OPA's Discovery feature.
    ///
    /// When the boot configuration includes a `discovery` section, this
    /// provider periodically downloads a "discovery bundle" from the
    /// configured service endpoint. The bundle is evaluated to produce
    /// a new OPA configuration. The discovered configuration is then
    /// merged with the boot configuration (boot values take precedence
    /// on conflicts) and returned to the Runtime for consumption.
    ///
    /// ## Merging Discovered Configs
    ///
    /// - **Dictionary fields** (`services`, `bundles`, `labels`, `keys`):
    ///   Boot config entries override on key conflicts.
    /// - **Discovery section**: Always preserved from the boot config.
    ///   Discovered changes are ignored entirely, per the OPA spec, to
    ///   prevent unrecoverable misconfigurations.
    /// - **Scalar / optional fields** (`decisionLogs`, `persistenceDirectory`):
    ///   Boot value wins if non-nil; otherwise the discovered value is used.
    ///
    /// ## Limitations
    ///
    /// - Bundle persistence of the discovery bundle itself is not yet
    ///   implemented. The bundle is re-downloaded on every startup.
    /// - Discovery bundle signature verification is not yet implemented.
    public struct DiscoveryConfigProvider: OPA.HTTPConfigProvider, Sendable {
        /// The immutable boot configuration, retained for merge precedence.
        private let bootConfig: OPA.Config

        /// The resolved discovery configuration, extracted once at init.
        private let discoveryConfig: OPA.DiscoveryConfig

        /// The bundle loader, constructed at init from the boot config.
        /// May mutate over time due to state caching in the loader.
        private var loader: any OPA.BundleLoader

        /// Logger instance to use for log messages.
        private var logger: Logger

        /// Query string derived from `discoveryConfig.decision` and used to
        /// evaluate the discovery bundle (`data` / `data.<dot.path>`).
        private let discoveryQuery: String

        /// Slash-form entrypoint derived from ``discoveryQuery``. A bundle
        /// that ships a plan must have a plan with this name.
        private let discoveryEntrypoint: String

        /// Pre-rendered plan.json ready to slot into ``Rego/BundleFile`` when
        /// a discovery bundle ships with no plan. Generated once at init via
        /// ``MiniPlanner``.
        private let fallbackPlanFile: Rego.BundleFile

        /// Constructs a DiscoveryConfigProvider from the provided boot config.
        public init(config: OPA.Config, logger: Logger? = nil) throws {
            try self.init(bootConfig: config, logger: logger)
        }

        /// Constructs a DiscoveryConfigProvider from the provided boot config.
        ///
        /// Fails immediately if:
        /// - The boot config has no `discovery` section.
        /// - No bundle loader is compatible with the discovery config.
        ///
        /// - Parameters:
        ///   - bootConfig: The boot configuration containing a `discovery` section.
        ///   - bundleLoaders: Bundle loader types to try, in priority order.
        public init(
            bootConfig: OPA.Config,
            bundleLoaders: [OPA.BundleLoader.Type] = [
                OPA.DiskBasedBundleLoader.self,
                OPA.RESTClientBundleLoader.self,
            ],
            logger: Logger? = nil
        ) throws {
            guard let discoveryConfig = bootConfig.discovery else {
                throw RuntimeError(
                    code: .internalError,
                    message: "Cannot create DiscoveryConfigProvider: no discovery section in boot config"
                )
            }

            self.bootConfig = bootConfig
            self.discoveryConfig = discoveryConfig

            // Derive the discovery query and slash-form entrypoint once, at
            // init time, so every subsequent `load()` uses the same values.
            // If the boot config changes, the Runtime replaces this provider
            // with a fresh instance.
            let query = Self.discoveryQuery(forDecision: discoveryConfig.decision)
            let entrypoint = try queryToEntryPoint(query)
            self.discoveryQuery = query
            self.discoveryEntrypoint = entrypoint

            // Pre-render a fallback plan.json so we can inject it into any
            // data-only discovery bundle without redoing the work per-load.
            let policy = try MiniPlanner.generate(query: query)
            let planData = try JSONEncoder().encode(policy)
            self.fallbackPlanFile = Rego.BundleFile(
                url: URL(string: "/plan.json")!,
                data: planData
            )

            // Find the first compatible loader and construct it.
            var constructed: (any OPA.BundleLoader)?
            for loaderType in bundleLoaders {
                if loaderType.compatibleWithDiscoveryConfig(config: bootConfig) {
                    constructed = try loaderType.init(discoveryConfig: bootConfig, logger: logger)
                    break
                }
            }

            guard let constructed else {
                throw RuntimeError(
                    code: .internalError,
                    message: "No compatible bundle loader found for discovery configuration"
                )
            }

            self.loader = constructed
            self.logger = logger ?? Logger(label: "swift-opa.config.discovery")
        }

        // MARK: - ConfigProvider

        /// Loads (or re-loads) the discovered configuration once.
        ///
        /// Fetches the discovery bundle via the underlying loader, evaluates
        /// it to produce a config, and merges it with the boot config. Bundles
        /// that ship with no plan get a ``MiniPlanner``-generated data-lookup
        /// plan injected so direct `data.<path>` discovery queries resolve
        /// against the bundle's data tree.
        public mutating func load() async -> Result<OPA.Config, any Swift.Error> {
            let result = await self.loader.load()

            switch result {
            case .success(let bundle):
                do {
                    let preparedBundle = try prepareBundleForEvaluation(bundle)
                    let discoveredConfig = try await Self.evaluateDiscoveryBundle(
                        bundle: preparedBundle,
                        query: discoveryQuery
                    )
                    let mergedConfig = try Self.mergeConfigs(
                        boot: bootConfig,
                        discovered: discoveredConfig
                    )
                    return .success(mergedConfig)
                } catch {
                    return .failure(error)
                }
            case .failure(let error):
                return .failure(error)
            }
        }

        // MARK: - Plan Injection / Validation

        /// Returns the bundle as-is when its existing plans cover the
        /// configured decision entrypoint, or a copy with a
        /// ``MiniPlanner``-generated plan attached when the bundle has no
        /// plan files.
        ///
        /// Throws a descriptive error when the bundle ships with IR plans
        /// but none match the configured `discovery.decision` path.
        private func prepareBundleForEvaluation(_ bundle: OPA.Bundle) throws -> OPA.Bundle {
            if bundle.planFiles.isEmpty {
                var injected = bundle
                injected.planFiles = [fallbackPlanFile]
                return injected
            }

            // Collect plan names from every planFile in the bundle. An
            // unparseable plan.json will error here rather than at query
            // preparation time.
            var planNames: [String] = []
            for planFile in bundle.planFiles {
                let policy = try IR.Policy(jsonData: planFile.data)
                planNames.append(contentsOf: policy.plans?.plans.map(\.name) ?? [])
            }

            guard planNames.contains(discoveryEntrypoint) else {
                throw RuntimeError(
                    code: .invalidArgumentError,
                    message: """
                        Discovery bundle ships plans \(planNames) but none matches the \
                        configured `discovery.decision` entrypoint "\(discoveryEntrypoint)". \
                        Either remove `discovery.decision` (or change it to match an existing plan), \
                        or rebuild the discovery bundle with a plan at that path.
                        """
                )
            }

            return bundle
        }

        // MARK: - HTTPConfigProvider

        public func isLongPollingEnabled() -> Bool {
            if let httpLoader = loader as? any OPA.HTTPBundleLoader {
                return httpLoader.isLongPollingEnabled()
            }
            return false
        }

        /// Returns the polling configuration for the discovery bundle,
        /// so that the Runtime's polling loop can honor it.
        func pollingConfig() -> OPA.PollingConfig? {
            return discoveryConfig.downloaderConfig.polling
        }

        // MARK: - Bundle Evaluation

        /// Builds the full query string used to evaluate a discovery bundle
        /// from the `discovery.decision` config value.
        ///
        /// Decision path convention (per the OPA spec):
        /// - `nil` / empty -> query `data`
        /// - `"example/discovery"` -> query `data.example.discovery`
        static func discoveryQuery(forDecision decision: String?) -> String {
            guard let decision, !decision.isEmpty else {
                return "data"
            }
            let dotPath = decision.trimmingCharacters(in: ["/"]).replacingOccurrences(of: "/", with: ".")
            return dotPath.hasPrefix("data.") ? dotPath : "data.\(dotPath)"
        }

        /// Evaluates the discovery bundle to produce a configuration.
        ///
        /// The discovery bundle is loaded into a temporary engine and the
        /// provided query is evaluated with an empty input. The result is
        /// JSON-round-tripped into an ``OPA.Config``.
        static func evaluateDiscoveryBundle(
            bundle: OPA.Bundle,
            query: String
        ) async throws -> OPA.Config {
            var engine = OPA.Engine(
                bundles: ["discovery": bundle],
                capabilities: nil,
                customBuiltins: [:]
            )
            let preparedQuery = try await engine.prepareForEvaluation(query: query)
            let resultValue = try await preparedQuery.evaluate(input: .object([:]))

            // The engine returns a Rego result set:
            //   [ { "<binding>": <value> }, ... ]
            // For discovery we expect exactly one result with exactly one binding.
            let unwrapped = try Self.unwrapDiscoveryResult(resultValue)

            // JSON round-trip: RegoValue -> Data -> OPA.Config
            let jsonData = try JSONEncoder().encode(unwrapped)
            return try JSONDecoder().decode(OPA.Config.self, from: jsonData)
        }

        // MARK: - Config Merging

        /// Merges a boot config with a discovered config.
        ///
        /// For all dictionary-typed fields, we start with the
        /// boot config, and only merge non-conflicting new entries
        /// from the discovered config.
        static func mergeConfigs(
            boot: OPA.Config,
            discovered: OPA.Config
        ) throws -> OPA.Config {
            var mergedServices = boot.services
            mergedServices.merge(discovered.services) { bootValue, _ in bootValue }

            var mergedLabels = boot.labels
            mergedLabels.merge(discovered.labels) { bootValue, _ in bootValue }

            var mergedBundles = boot.bundles
            mergedBundles.merge(discovered.bundles) { bootValue, _ in bootValue }

            var mergedPlugins = boot.plugins ?? [:]
            mergedPlugins.merge(discovered.plugins ?? [:]) { bootValue, _ in bootValue }

            var mergedKeys = boot.keys
            mergedKeys.merge(discovered.keys) { bootValue, _ in bootValue }

            // Scalar / optional fields: boot wins when non-nil.
            return try OPA.Config(
                services: mergedServices,
                labels: mergedLabels,
                discovery: boot.discovery,  // Immutable — never overridden by discovery.
                bundles: mergedBundles,
                decisionLogs: boot.decisionLogs ?? discovered.decisionLogs,
                plugins: mergedPlugins,
                keys: mergedKeys,
                persistenceDirectory: boot.persistenceDirectory ?? discovered.persistenceDirectory
            )
        }

        /// Extracts the single discovery config value from a Rego `ResultSet`.
        ///
        /// Expected shape: a set with exactly one element, where that element is
        /// an object with exactly one binding. Returns the bound value.
        private static func unwrapDiscoveryResult(_ resultSet: Rego.ResultSet) throws -> AST.RegoValue {
            guard resultSet.count == 1, let only = resultSet.first else {
                throw RuntimeError(
                    code: .internalError,
                    message: "Discovery evaluation returned \(resultSet.count) results; expected exactly 1"
                )
            }
            guard case .object(let bindings) = only else {
                throw RuntimeError(
                    code: .internalError,
                    message: "Discovery result entry is not an object"
                )
            }
            guard bindings.count == 1, let value = bindings.first?.value else {
                throw RuntimeError(
                    code: .internalError,
                    message: "Discovery result entry has \(bindings.count) bindings; expected exactly 1"
                )
            }
            return value
        }
    }
}
