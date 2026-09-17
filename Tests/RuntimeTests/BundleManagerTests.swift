import Config
import Foundation
import Logging
import Rego
import Synchronization
import Testing

@testable import Runtime

// MARK: - Instantiation tracking

/// Process-wide count of how many times a loader was constructed for a given
/// bundle name. Tests use unique names so counts never collide across the
/// parallel test runner.
private enum ReconcilerLoaderStats {
    static let counts = Mutex<[String: Int]>([:])
    static func recordInit(name: String) {
        counts.withLock { $0[name, default: 0] += 1 }
    }
    static func count(_ name: String) -> Int {
        counts.withLock { $0[name] ?? 0 }
    }
}

/// Socket-free ``OPA.BundleLoader`` that records each construction and emits one
/// bundle before parking until cancelled. Selected by the factory because it is
/// compatible with any config.
private struct ReconcilerMockLoader: OPA.BundleLoader {
    let name: String
    let bundle: OPA.Bundle
    var emitted = false

    init(config: OPA.Config, bundleResourceName: String, logger: Logger?) throws {
        self.name = bundleResourceName
        self.bundle = try makeExampleBundle()
        ReconcilerLoaderStats.recordInit(name: bundleResourceName)
    }

    mutating func load() async -> OPA.BundleUpdate {
        if !emitted {
            emitted = true
            return .downloaded(bundle, etag: nil, size: nil)
        }
        while !Task.isCancelled { await Task.yield() }
        return .downloaded(bundle, etag: nil, size: nil)
    }

    static func compatibleWithConfig(config: OPA.Config, bundleResourceName: String) -> Bool { true }
}

/// A loader compatible with nothing, so ``OPA/BundleLoaderFactory`` throws when
/// asked to build it — exercising the failed-construction path.
private struct NeverCompatibleLoader: OPA.BundleLoader {
    init(config: OPA.Config, bundleResourceName: String, logger: Logger?) throws {}
    func load() async -> OPA.BundleUpdate {
        .failed(RuntimeError(code: .internalError, message: "never constructed"))
    }
    static func compatibleWithConfig(config: OPA.Config, bundleResourceName: String) -> Bool { false }
}

// MARK: - Helpers

private func makeConfig(bundles: [String: String]) throws -> OPA.Config {
    let entries =
        bundles
        .map { "\"\($0.key)\": {\"service\": \"s\", \"resource\": \"\($0.value)\"}" }
        .joined(separator: ",")
    let json = """
        {"services": {"s": {"url": "https://example.com/"}}, "bundles": {\(entries)}}
        """
    let decoder = JSONDecoder()
    decoder.userInfo[.skipValidationOPAConfig] = true
    return try decoder.decode(OPA.Config.self, from: Data(json.utf8))
}

private func makeManager(
    onRemoved: (@Sendable (Set<String>) -> Void)? = nil
) -> OPA.BundleManager {
    let factory = OPA.BundleLoaderFactory(
        loaderTypes: [ReconcilerMockLoader.self], logger: Logger(label: "test"))
    return OPA.BundleManager(
        factory: factory,
        httpClientCache: nil,
        sink: { _, _ in },
        onRemoved: onRemoved,
        logger: Logger(label: "test"))
}

private func waitUntil(_ condition: @escaping @Sendable () -> Bool, iterations: Int = 100_000) async {
    var i = 0
    while !condition() && i < iterations {
        await Task.yield()
        i += 1
    }
}

// MARK: - Tests

@Suite("BundleManager reconcile")
struct BundleManagerTests {
    @Test("unchanged entries keep their loader across a config change")
    func unchangedEntriesPersist() async throws {
        let id = UUID().uuidString.prefix(8)
        let (a, b, c) = ("a-\(id)", "b-\(id)", "c-\(id)")
        let manager = makeManager()

        await manager.apply(config: try makeConfig(bundles: [a: "/r", b: "/r"]))
        #expect(ReconcilerLoaderStats.count(a) == 1)
        #expect(ReconcilerLoaderStats.count(b) == 1)

        // Adding c must not rebuild a or b.
        await manager.apply(config: try makeConfig(bundles: [a: "/r", b: "/r", c: "/r"]))
        #expect(ReconcilerLoaderStats.count(a) == 1)
        #expect(ReconcilerLoaderStats.count(b) == 1)
        #expect(ReconcilerLoaderStats.count(c) == 1)

        await manager.shutdown()
    }

    @Test("a changed entry restarts its loader")
    func changedEntryRestarts() async throws {
        let id = UUID().uuidString.prefix(8)
        let a = "a-\(id)"
        let manager = makeManager()

        await manager.apply(config: try makeConfig(bundles: [a: "/r1"]))
        #expect(ReconcilerLoaderStats.count(a) == 1)

        // Same name, different resource → fingerprint changes → restart.
        await manager.apply(config: try makeConfig(bundles: [a: "/r2"]))
        #expect(ReconcilerLoaderStats.count(a) == 2)

        await manager.shutdown()
    }

    @Test("removed entries are pruned via onRemoved")
    func removedEntriesPruned() async throws {
        let id = UUID().uuidString.prefix(8)
        let (a, b) = ("a-\(id)", "b-\(id)")
        let removed = Mutex<Set<String>>([])
        let manager = makeManager(onRemoved: { names in
            removed.withLock { $0.formUnion(names) }
        })

        await manager.apply(config: try makeConfig(bundles: [a: "/r", b: "/r"]))
        #expect(removed.withLock { $0 }.isEmpty)

        // Dropping b must fire onRemoved for b only (a is unchanged).
        await manager.apply(config: try makeConfig(bundles: [a: "/r"]))
        #expect(removed.withLock { $0 } == [b])
        #expect(ReconcilerLoaderStats.count(a) == 1)  // a not rebuilt

        await manager.shutdown()
    }

    @Test("a bundle whose loader fails to construct is pruned when it leaves the config")
    func failedConstructionEntryPruned() async throws {
        let id = UUID().uuidString.prefix(8)
        let x = "x-\(id)"
        let failed = Mutex<Set<String>>([])
        let removed = Mutex<Set<String>>([])
        let factory = OPA.BundleLoaderFactory(
            loaderTypes: [NeverCompatibleLoader.self], logger: Logger(label: "test"))
        let manager = OPA.BundleManager(
            factory: factory,
            httpClientCache: nil,
            sink: { name, update in
                if case .failed = update { failed.withLock { $0.insert(name) } }
            },
            onRemoved: { names in removed.withLock { $0.formUnion(names) } },
            logger: Logger(label: "test"))

        // No compatible loader → construction fails → reported as `.failed` and
        // never entered `running`.
        await manager.apply(config: try makeConfig(bundles: [x: "/r"]))
        #expect(failed.withLock { $0 } == [x])
        #expect(removed.withLock { $0 }.isEmpty)

        // Dropping x must still fire onRemoved so its stale status entry is pruned.
        await manager.apply(config: try makeConfig(bundles: [:]))
        #expect(removed.withLock { $0 } == [x])

        await manager.shutdown()
    }

    @Test("standalone: run(configs:) drives from a stream with a public HTTPClientCache")
    func standaloneRunFromStream() async throws {
        let id = UUID().uuidString.prefix(8)
        let a = "a-\(id)"
        // Assemble the building blocks with no Runtime, using the public cache init.
        let cache = OPA.HTTPClientCache(logger: Logger(label: "test"))
        let factory = OPA.BundleLoaderFactory(
            loaderTypes: [ReconcilerMockLoader.self], httpClientCache: cache, logger: Logger(label: "test"))
        let manager = OPA.BundleManager(
            factory: factory, httpClientCache: cache, sink: { _, _ in }, logger: Logger(label: "test"))

        let (stream, cont) = AsyncStream<OPA.Config>.makeStream()
        let task = Task { await manager.run(configs: stream) }
        cont.yield(try makeConfig(bundles: [a: "/r"]))
        await waitUntil { ReconcilerLoaderStats.count(a) == 1 }
        #expect(ReconcilerLoaderStats.count(a) == 1)

        task.cancel()
        cont.finish()
        await task.value
        await cache.shutdownAll()
    }
}
