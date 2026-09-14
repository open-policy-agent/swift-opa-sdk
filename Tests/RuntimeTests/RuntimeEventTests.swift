import Config
import Foundation
import Rego
import Testing

@testable import Runtime

// MARK: - Kind inspection helpers

extension OPA.RuntimeEvent.Kind {
    fileprivate var isFetchStarted: Bool {
        if case .fetchStarted = self { return true }
        return false
    }
    fileprivate var isUpdated: Bool {
        if case .updated = self { return true }
        return false
    }
    /// The revision of an `.updated` kind, or `nil` for other kinds (and for
    /// an `.updated` that carries no revision). Pair with ``isUpdated`` when the
    /// distinction matters.
    fileprivate var updatedRevision: String? {
        if case .updated(let revision) = self { return revision }
        return nil
    }
    fileprivate var failure: (code: RuntimeError.Code, httpStatus: Int?)? {
        if case .failed(let code, let httpStatus) = self { return (code, httpStatus) }
        return nil
    }
    fileprivate var isRunStarted: Bool {
        if case .runStarted = self { return true }
        return false
    }
    fileprivate var isRunStopped: Bool {
        if case .runStopped = self { return true }
        return false
    }
}

private func makeEvent(_ index: Int) -> OPA.RuntimeEvent {
    OPA.RuntimeEvent(source: .bundle(name: "b"), kind: .updated(revision: String(index)))
}

/// Drains a hub stream's events, collecting every event.
private func drainEvents(_ stream: AsyncStream<OPA.RuntimeEvent>) async -> [OPA.RuntimeEvent] {
    var out: [OPA.RuntimeEvent] = []
    for await event in stream { out.append(event) }
    return out
}

extension Sequence where Element == OPA.RuntimeEvent {
    /// The revisions of the `.updated` events, in order (skips other kinds).
    fileprivate var revisions: [String] { compactMap { $0.kind.updatedRevision } }
}

// MARK: - Hub unit tests

@Suite("RuntimeEventHub")
struct RuntimeEventHubTests {

    @Test("unbounded subscriber sees every event in order (no coalescing)")
    func noMissedEventsUnbounded() async {
        let hub = RuntimeEventHub()
        let stream = hub.subscribe()  // .unbounded default

        let count = 100
        for i in 0..<count { hub.yield(makeEvent(i)) }
        hub.finish()

        let received = await drainEvents(stream).revisions
        #expect(received == (0..<count).map(String.init))
    }

    @Test("every subscriber receives every event (multicast, not competing)")
    func multicast() async {
        let hub = RuntimeEventHub()
        let a = hub.subscribe()
        let b = hub.subscribe()

        let count = 20
        for i in 0..<count { hub.yield(makeEvent(i)) }
        hub.finish()

        async let ra = drainEvents(a)
        async let rb = drainEvents(b)
        let (eventsA, eventsB) = await (ra, rb)
        let expected = (0..<count).map(String.init)
        #expect(eventsA.revisions == expected)
        #expect(eventsB.revisions == expected)
    }

    @Test("late subscribers get future events only (no replay)")
    func noReplay() async {
        let hub = RuntimeEventHub()
        let a = hub.subscribe()
        hub.yield(makeEvent(1))  // only A is subscribed
        let b = hub.subscribe()
        hub.yield(makeEvent(2))  // both subscribed
        hub.finish()

        async let ra = drainEvents(a)
        async let rb = drainEvents(b)
        let (eventsA, eventsB) = await (ra, rb)
        #expect(eventsA.revisions == ["1", "2"])
        #expect(eventsB.revisions == ["2"], "B subscribed after event 1, so it must not replay it")
    }

    @Test("bounded buffering policy coalesces for that subscriber only")
    func boundedBufferingCoalesces() async {
        let hub = RuntimeEventHub()
        let bounded = hub.subscribe(bufferingPolicy: .bufferingNewest(1))
        let unbounded = hub.subscribe()  // control

        for i in 0..<5 { hub.yield(makeEvent(i)) }
        hub.finish()

        let boundedResult = await drainEvents(bounded).revisions
        let unboundedResult = await drainEvents(unbounded).revisions
        #expect(boundedResult == ["4"], "bufferingNewest(1) keeps only the newest undrained event")
        #expect(unboundedResult == ["0", "1", "2", "3", "4"], "the unbounded subscriber is unaffected")
    }

    @Test("finish ends active loops and rejects late subscribers")
    func finishClosesStreams() async {
        let hub = RuntimeEventHub()
        let stream = hub.subscribe()
        hub.finish()

        var count = 0
        for await _ in stream { count += 1 }
        #expect(count == 0, "an empty finished stream ends immediately")

        // Subscribing after finish yields an already-finished stream.
        let late = hub.subscribe()
        var lateCount = 0
        for await _ in late { lateCount += 1 }
        #expect(lateCount == 0)
    }
}

// MARK: - Runtime integration tests

@Suite("Runtime event stream")
struct RuntimeEventStreamTests {

    private func mockConfig(id: String, bundleName: String = "test") throws -> OPA.Config {
        let json = """
            {
              "services": {"svc": {"url": "https://example.com"}},
              "bundles": {"\(bundleName)": {"service": "svc", "resource": "/b"}},
              "plugins": {"mock_loader": {"id": "\(id)"}}
            }
            """
        return try JSONDecoder().decode(OPA.Config.self, from: Data(json.utf8))
    }

    /// Collects events until `predicate` matches (inclusive) or the timeout
    /// elapses, then returns what was collected.
    private func collect(
        _ stream: some (AsyncSequence<OPA.RuntimeEvent, Never> & Sendable),
        timeout: Duration = .seconds(10),
        until predicate: @escaping @Sendable (OPA.RuntimeEvent) -> Bool
    ) async -> [OPA.RuntimeEvent] {
        let collector = Task { () -> [OPA.RuntimeEvent] in
            var events: [OPA.RuntimeEvent] = []
            for await event in stream {
                events.append(event)
                if predicate(event) { break }
            }
            return events
        }
        let watchdog = Task {
            try? await Task.sleep(for: timeout)
            collector.cancel()
        }
        let events = await collector.value
        watchdog.cancel()
        return events
    }

    @Test("a successful load emits fetchStarted then updated(revision)")
    func fetchStartedThenUpdated() async throws {
        let bundle = try makeExampleBundle(
            manifest: OPA.Manifest(revision: "rev-abc", roots: ["foo"]))
        let id = MockBundleLoaderRegistry.shared.register(scripted: [.success(bundle)])
        defer { MockBundleLoaderRegistry.shared.unregister(id: id) }

        let runtime = try OPA.Runtime(
            config: try mockConfig(id: id),
            bundleLoaders: [OPA.MockBundleLoader.self])
        let stream = runtime.events()

        let runTask = Task { try await runtime.run() }
        defer { runTask.cancel() }

        let events = await collect(stream) { event in
            event.source == .bundle(name: "test") && event.kind.isUpdated
        }

        let updatedIndex = events.firstIndex { $0.kind.isUpdated }
        let updated = try #require(updatedIndex, "should observe an .updated event")
        #expect(events[updated].kind.updatedRevision == "rev-abc")
        // A fetchStarted for the same source must precede it.
        let startedBefore = events[..<updated].contains {
            $0.source == .bundle(name: "test") && $0.kind.isFetchStarted
        }
        #expect(startedBefore, "an .updated must be preceded by a .fetchStarted")

        runTask.cancel()
        _ = try? await runTask.value
    }

    @Test("a failed load emits failed(code, httpStatus)")
    func failedCarriesCodeAndStatus() async throws {
        let error = BundleFetchError(
            code: .bundleLoadError, message: "boom", httpStatus: 503, host: "example.com")
        let id = MockBundleLoaderRegistry.shared.register(scripted: [.failure(error)])
        defer { MockBundleLoaderRegistry.shared.unregister(id: id) }

        let runtime = try OPA.Runtime(
            config: try mockConfig(id: id),
            bundleLoaders: [OPA.MockBundleLoader.self])
        let stream = runtime.events()

        let runTask = Task { try await runtime.run() }
        defer { runTask.cancel() }

        let events = await collect(stream) { event in
            event.source == .bundle(name: "test") && event.kind.failure != nil
        }

        let failed = try #require(events.first { $0.kind.failure != nil })
        let info = try #require(failed.kind.failure)
        #expect(info.code == .bundleLoadError)
        #expect(info.httpStatus == 503)

        runTask.cancel()
        _ = try? await runTask.value
    }

    @Test("a loader-setup failure emits a paired fetchStarted then failed")
    func setupFailureIsPaired() async throws {
        // No compatible loader types, so `getBundleLoader` throws during setup.
        let runtime = try OPA.Runtime(config: try mockConfig(id: "unused"), bundleLoaders: [])
        let stream = runtime.events()

        let runTask = Task { try await runtime.run() }
        defer { runTask.cancel() }

        let events = await collect(stream) { event in
            event.source == .bundle(name: "test") && event.kind.failure != nil
        }

        let failedIndex = try #require(events.firstIndex { $0.kind.failure != nil })
        // A fetchStarted for the same source must precede the failure.
        let startedBefore = events[..<failedIndex].contains {
            $0.source == .bundle(name: "test") && $0.kind.isFetchStarted
        }
        #expect(startedBefore, "a setup failure must still be preceded by a .fetchStarted")

        runTask.cancel()
        _ = try? await runTask.value
    }

    @Test("cancelling run() emits runStopped without finishing the subscription")
    func runEndEmitsRunStopped() async throws {
        let id = MockBundleLoaderRegistry.shared.register(
            scripted: [.success(try makeExampleBundle())])
        defer { MockBundleLoaderRegistry.shared.unregister(id: id) }

        let runtime = try OPA.Runtime(
            config: try mockConfig(id: id),
            bundleLoaders: [OPA.MockBundleLoader.self])
        let stream = runtime.events()

        let runTask = Task { try await runtime.run() }
        try await Task.sleep(for: .milliseconds(50))  // let run() enter its loop
        runTask.cancel()
        _ = try? await runTask.value

        // The stream stays open (no auto-finish on run end). Collecting until
        // runStopped must terminate on the event, not on iterator closure.
        let events = await collect(stream) { $0.kind.isRunStopped }
        #expect(events.last?.kind.isRunStopped == true, "cancelling run() must emit runStopped")
        #expect(events.first?.kind.isRunStarted == true, "the session must have opened with runStarted")
    }

    @Test("one subscription observes runStarted/runStopped across a restart")
    func subscriptionSpansRestart() async throws {
        let id = MockBundleLoaderRegistry.shared.register(
            scripted: [.success(try makeExampleBundle()), .success(try makeExampleBundle())])
        defer { MockBundleLoaderRegistry.shared.unregister(id: id) }

        let runtime = try OPA.Runtime(
            config: try mockConfig(id: id),
            bundleLoaders: [OPA.MockBundleLoader.self])
        // Subscribe before the first run() to capture the whole lifetime.
        let stream = runtime.events()

        // Collect the full sequence in the background across two sessions.
        let collector = Task { () -> [OPA.RuntimeEvent] in
            var out: [OPA.RuntimeEvent] = []
            var stopCount = 0
            for await event in stream {
                out.append(event)
                if event.kind.isRunStopped {
                    stopCount += 1
                    if stopCount == 2 { break }
                }
            }
            return out
        }

        for _ in 0..<2 {
            let runTask = Task { try await runtime.run() }
            try await Task.sleep(for: .milliseconds(50))
            runTask.cancel()
            _ = try? await runTask.value
        }

        let lifecycle = await collector.value.map { $0.kind }.filter {
            $0.isRunStarted || $0.isRunStopped
        }
        // The same subscription saw both sessions bracketed in order.
        #expect(lifecycle.count == 4)
        #expect(lifecycle[0].isRunStarted)
        #expect(lifecycle[1].isRunStopped)
        #expect(lifecycle[2].isRunStarted)
        #expect(lifecycle[3].isRunStopped)
    }

    @Test("deallocating the Runtime finishes subscriptions")
    func deinitFinishesStreams() async throws {
        let id = MockBundleLoaderRegistry.shared.register(
            scripted: [.success(try makeExampleBundle())])
        defer { MockBundleLoaderRegistry.shared.unregister(id: id) }

        var runtime: OPA.Runtime? = try OPA.Runtime(
            config: try mockConfig(id: id),
            bundleLoaders: [OPA.MockBundleLoader.self])
        let stream = runtime!.events()

        // Drop the only strong reference; deinit must finish the hub.
        runtime = nil

        var count = 0
        for await _ in stream { count += 1 }
        // Reaching here means the stream finished rather than hanging.
        #expect(count == 0)
    }
}
