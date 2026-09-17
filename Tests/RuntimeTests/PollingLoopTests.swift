import Config
import Foundation
import Logging
import Rego
import Synchronization
import Testing

@testable import Runtime

// MARK: - Test doubles

private struct LoopTestError: Error, Equatable, Sendable {
    var tag: String = "boom"
}

/// Scripted, socket-free ``OPA.HTTPBundleLoader`` for exercising the
/// self-driving polling loop directly (no Runtime, no network). Returns each
/// scripted result once, then parks until cancelled so the loop stops emitting.
private struct ScriptedBundleLoader: OPA.HTTPBundleLoader {
    let script: [Result<OPA.Bundle, LoopTestError>]
    var index = 0
    let longPolling: Bool

    init(script: [Result<OPA.Bundle, LoopTestError>], longPolling: Bool = false) {
        self.script = script
        self.longPolling = longPolling
    }

    // Protocol-required initializers — unused by the loop tests.
    init(config: OPA.Config, bundleResourceName: String, logger: Logger?) throws {
        self.script = []
        self.longPolling = false
    }
    init(
        config: OPA.Config, bundleResourceName: String, etag: String?, headers: [String: String]?,
        httpClientConfig: OPA.HTTPClientConfigSource?, httpClientCache: OPA.HTTPClientCache?, logger: Logger?
    ) throws {
        self.script = []
        self.longPolling = false
    }

    mutating func load() async -> OPA.BundleUpdate {
        if index < script.count {
            let step = script[index]
            index += 1
            switch step {
            case .success(let bundle): return .downloaded(bundle, etag: nil, size: nil)
            case .failure(let error): return .failed(error)
            }
        }
        // Script exhausted: park until cancelled so the loop stops emitting.
        while !Task.isCancelled { await Task.yield() }
        return .failed(LoopTestError(tag: "exhausted"))
    }

    func isLongPollingEnabled() -> Bool { longPolling }

    static func compatibleWithConfig(config: OPA.Config, bundleResourceName: String) -> Bool { true }
}

/// Scripted, socket-free ``OPA.HTTPConfigProvider`` mirroring
/// ``ScriptedBundleLoader`` for the config-provider loop.
private struct ScriptedConfigProvider: OPA.HTTPConfigProvider {
    let script: [Result<OPA.Config, LoopTestError>]
    var index = 0
    let longPolling: Bool

    init(script: [Result<OPA.Config, LoopTestError>], longPolling: Bool = false) {
        self.script = script
        self.longPolling = longPolling
    }

    init(config: OPA.Config, logger: Logger?) throws {
        self.script = []
        self.longPolling = false
    }

    mutating func load() async -> Result<OPA.Config, any Swift.Error> {
        if index < script.count {
            let step = script[index]
            index += 1
            return step.mapError { $0 as any Swift.Error }
        }
        while !Task.isCancelled { await Task.yield() }
        return .failure(LoopTestError(tag: "exhausted"))
    }

    func isLongPollingEnabled() -> Bool { longPolling }
}

private func emptyConfig() throws -> OPA.Config {
    let decoder = JSONDecoder()
    decoder.userInfo[.skipValidationOPAConfig] = true
    return try decoder.decode(OPA.Config.self, from: Data("{}".utf8))
}

// MARK: - Collectors

/// Runs a bundle loop, returning the first `count` updates it emits. The loop
/// keeps running (parked) until cancelled, which this helper does before return.
private func collectBundleUpdates(
    count: Int,
    wait: @escaping @Sendable (Int64) async throws -> Void = { _ in },
    loader: ScriptedBundleLoader
) async -> [OPA.BundleUpdate] {
    let (stream, cont) = AsyncStream<OPA.BundleUpdate>.makeStream()
    let sink: OPA.BundleUpdateSink = { _, update in cont.yield(update) }
    let task = Task {
        var loader = loader
        await OPA.Polling.runBundleLoop(&loader, name: "test", into: sink, wait: wait)
    }
    var collected: [OPA.BundleUpdate] = []
    for await update in stream {
        collected.append(update)
        if collected.count >= count { break }
    }
    task.cancel()
    cont.finish()
    await task.value
    return collected
}

/// Config-provider analogue of ``collectBundleUpdates``.
private func collectConfigUpdates(
    count: Int,
    wait: @escaping @Sendable (Int64) async throws -> Void = { _ in },
    provider: ScriptedConfigProvider
) async -> [OPA.ConfigUpdate] {
    let (stream, cont) = AsyncStream<OPA.ConfigUpdate>.makeStream()
    let sink: OPA.ConfigUpdateSink = { update in cont.yield(update) }
    let task = Task {
        var provider = provider
        await OPA.Polling.runConfigLoop(&provider, into: sink, wait: wait)
    }
    var collected: [OPA.ConfigUpdate] = []
    for await update in stream {
        collected.append(update)
        if collected.count >= count { break }
    }
    task.cancel()
    cont.finish()
    await task.value
    return collected
}

// MARK: - Bundle loop tests

@Suite("Self-driving bundle loop")
struct PollingLoopTests {
    @Test("emits loaded/failed updates in script order, preserving payloads")
    func emitsInOrder() async throws {
        let b1 = try makeExampleBundle()
        let b2 = try makeExampleBundle()
        let loader = ScriptedBundleLoader(script: [.success(b1), .failure(LoopTestError()), .success(b2)])

        let updates = await collectBundleUpdates(count: 3, loader: loader)

        #expect(updates.count == 3)
        guard case .downloaded(let first, _, _) = updates[0] else {
            Issue.record("expected .downloaded, got \(updates[0])")
            return
        }
        #expect(first == b1)
        guard case .failed = updates[1] else {
            Issue.record("expected .failed, got \(updates[1])")
            return
        }
        guard case .downloaded(let third, _, _) = updates[2] else {
            Issue.record("expected .downloaded, got \(updates[2])")
            return
        }
        #expect(third == b2)
    }

    @Test("cancellation stops the loop cleanly")
    func cancellationStops() async throws {
        let b1 = try makeExampleBundle()
        let loader = ScriptedBundleLoader(script: [.success(b1)])

        // If cancellation did not terminate the loop, this would hang.
        let updates = await collectBundleUpdates(count: 1, loader: loader)
        #expect(updates.count == 1)
    }

    @Test("long-polling loaders skip the inter-poll wait")
    func longPollingSkipsWait() async throws {
        let b = try makeExampleBundle()
        let waitCount = Mutex<Int>(0)
        let loader = ScriptedBundleLoader(
            script: [.success(b), .success(b), .success(b)], longPolling: true)

        let updates = await collectBundleUpdates(
            count: 3, wait: { _ in waitCount.withLock { $0 += 1 } }, loader: loader)

        #expect(updates.count == 3)
        #expect(waitCount.withLock { $0 } == 0)
    }

    @Test("normal loaders wait between polls")
    func normalPollingWaits() async throws {
        let b = try makeExampleBundle()
        let waitCount = Mutex<Int>(0)
        let loader = ScriptedBundleLoader(script: [.success(b), .success(b)], longPolling: false)

        let updates = await collectBundleUpdates(
            count: 2, wait: { _ in waitCount.withLock { $0 += 1 } }, loader: loader)

        #expect(updates.count == 2)
        #expect(waitCount.withLock { $0 } >= 1)
    }
}

// MARK: - Config provider loop tests

@Suite("Self-driving config provider loop")
struct ConfigLoopTests {
    @Test("emits updated/failed config in script order")
    func emitsInOrder() async throws {
        let cfg = try emptyConfig()
        let provider = ScriptedConfigProvider(script: [.success(cfg), .failure(LoopTestError()), .success(cfg)])

        let updates = await collectConfigUpdates(count: 3, provider: provider)

        #expect(updates.count == 3)
        guard case .updated = updates[0] else {
            Issue.record("expected .updated, got \(updates[0])")
            return
        }
        guard case .failed = updates[1] else {
            Issue.record("expected .failed, got \(updates[1])")
            return
        }
        guard case .updated = updates[2] else {
            Issue.record("expected .updated, got \(updates[2])")
            return
        }
    }

    @Test("long-polling providers skip the inter-poll wait")
    func longPollingSkipsWait() async throws {
        let cfg = try emptyConfig()
        let waitCount = Mutex<Int>(0)
        let provider = ScriptedConfigProvider(
            script: [.success(cfg), .success(cfg), .success(cfg)], longPolling: true)

        let updates = await collectConfigUpdates(
            count: 3, wait: { _ in waitCount.withLock { $0 += 1 } }, provider: provider)

        #expect(updates.count == 3)
        #expect(waitCount.withLock { $0 } == 0)
    }

    @Test("normal providers wait between polls")
    func normalPollingWaits() async throws {
        let cfg = try emptyConfig()
        let waitCount = Mutex<Int>(0)
        let provider = ScriptedConfigProvider(script: [.success(cfg), .success(cfg)], longPolling: false)

        let updates = await collectConfigUpdates(
            count: 2, wait: { _ in waitCount.withLock { $0 += 1 } }, provider: provider)

        #expect(updates.count == 2)
        #expect(waitCount.withLock { $0 } >= 1)
    }
}
