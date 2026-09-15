import Config
import Rego

extension OPA {
    /// One outcome of a single poll, emitted by a self-driving bundle loader.
    public enum BundleUpdate: Sendable {
        /// A bundle was fetched and parsed. May be byte-identical to the previous one.
        case loaded(OPA.Bundle)
        /// The fetch or parse failed.
        case failed(any Swift.Error)
    }

    /// One outcome of a single config-provider poll.
    public enum ConfigUpdate: Sendable {
        /// A configuration was produced.
        case updated(OPA.Config)
        /// The load failed.
        case failed(any Swift.Error)
    }

    /// Sink a self-driving bundle loader reports each poll into.
    ///
    /// `Sendable` so it can be captured by a per-loader `Task`. Implementations
    /// route into a short synchronous critical section and must not hold a lock
    /// across an `await`.
    public typealias BundleUpdateSink = @Sendable (_ name: String, _ update: OPA.BundleUpdate) -> Void

    /// Sink a self-driving config provider reports each poll into. Same
    /// concurrency contract as ``BundleUpdateSink``.
    public typealias ConfigUpdateSink = @Sendable (_ update: OPA.ConfigUpdate) -> Void

    /// Shared helpers for the self-driving polling loops.
    public enum Polling {
        /// Picks a random inter-poll delay (jitter) within the configured
        /// window, falling back to the ``OPA/PollingConfig`` defaults.
        public static func nextDelaySeconds(_ polling: OPA.PollingConfig?) -> Int64 {
            let lower = polling?.minDelaySeconds ?? OPA.PollingConfig.defaultMinDelaySeconds
            let upper = polling?.maxDelaySeconds ?? OPA.PollingConfig.defaultMaxDelaySeconds
            return Int64.random(in: lower...upper)
        }

        /// Drives a bundle loader's polling loop over an exclusively-held loader
        /// until the enclosing `Task` is cancelled, reporting each poll to `sink`.
        ///
        /// `wait` is injectable so tests can run the loop with zero delay and
        /// drive termination via cancellation. Long-polling loaders skip the
        /// inter-poll wait (the wait already happened inside `load()`).
        public static func runBundleLoop<L: OPA.BundleLoader>(
            _ loader: inout L,
            name: String,
            into sink: @escaping OPA.BundleUpdateSink,
            wait: @Sendable (Int64) async throws -> Void = { try await Task.sleep(for: .seconds($0)) }
        ) async {
            while !Task.isCancelled {
                let result = await loader.load()
                if Task.isCancelled { break }  // don't report a poll that raced cancellation
                switch result {
                case .success(let bundle): sink(name, .loaded(bundle))
                case .failure(let error): sink(name, .failed(error))
                }
                let longPoll = (loader as? any OPA.HTTPBundleLoader)?.isLongPollingEnabled() ?? false
                if longPoll { continue }
                do { try await wait(nextDelaySeconds(loader.pollingConfig)) } catch { break }
            }
        }

        /// Config-provider analogue of ``runBundleLoop(_:name:into:wait:)``.
        public static func runConfigLoop<P: OPA.ConfigProvider>(
            _ provider: inout P,
            into sink: @escaping OPA.ConfigUpdateSink,
            wait: @Sendable (Int64) async throws -> Void = { try await Task.sleep(for: .seconds($0)) }
        ) async {
            while !Task.isCancelled {
                let result = await provider.load()
                if Task.isCancelled { break }
                switch result {
                case .success(let config): sink(.updated(config))
                case .failure(let error): sink(.failed(error))
                }
                let longPoll = (provider as? any OPA.HTTPConfigProvider)?.isLongPollingEnabled() ?? false
                if longPoll { continue }
                do { try await wait(nextDelaySeconds(provider.pollingConfig())) } catch { break }
            }
        }
    }
}
