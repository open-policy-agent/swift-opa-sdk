import Foundation
import Rego

// MARK: - BundleStore

extension OPA {
    /// This type tracks the set of active bundles and the last recorded fetch
    /// attempts for each.
    ///
    /// It is not thread safe on its own, so users must guard access with a
    /// mutex around it.
    struct BundleStore: Sendable {
        /// A currently-enforced bundle and its activation provenance.
        struct Live: Sendable {
            var bundle: OPA.Bundle
            var revision: String
            var lastSuccessfulActivation: Date
        }

        /// The last observed fetch state for a bundle (whether or not anything
        /// is live for it).
        struct Fetch: Sendable, Equatable {
            var lastRequest: Date?
            var lastSuccessfulRequest: Date?
            var lastSuccessfulDownload: Date?
            var etag: String = ""
            var size: Int?
            var type: String?
            var code: String?
            var message: String?
            var httpCode: Int?
            var errors: [OPA.StatusError]?

            mutating func clearError() {
                code = nil
                message = nil
                httpCode = nil
                errors = nil
            }

            mutating func recordError(code: String, message: String, httpCode: Int? = nil) {
                self.code = code
                self.message = message
                self.httpCode = httpCode
                self.errors = [OPA.StatusError(message: message)]
            }

            /// Extracts `code`/`message`/`httpCode` from the SDK's structured
            /// error types without parsing message strings. Uses the
            /// ``RuntimeError/Code`` vocabulary for `code` throughout, so the
            /// surfaced codes stay consistent across error kinds.
            mutating func recordError(from error: any Swift.Error) {
                let code: String
                let message: String
                if let failure = error as? any RuntimeFailure {
                    code = failure.code.description
                    message = failure.message
                } else {
                    code = RuntimeError.Code.internalError.description
                    message = String(describing: error)
                }
                let httpCode = (error as? BundleFetchError)?.httpStatus
                recordError(code: code, message: message, httpCode: httpCode)
            }
        }

        private(set) var live: [String: Live] = [:]
        private(set) var fetch: [String: Fetch] = [:]
        private(set) var bundles: [String: OPA.Bundle] = [:]
        private(set) var generation: UInt64 = 0

        /// Updates the store with the results of a bundle poll attempt. Returns
        /// `true` when the active set changed (a new bundle was activated).
        @discardableResult
        mutating func update(name: String, _ event: OPA.BundleUpdate, now: Date) -> Bool {
            var f = fetch[name] ?? Fetch()
            f.lastRequest = now
            var activated = false

            switch event {
            case .downloaded(let bundle, let etag, let size):
                // Bundle source provided a full bundle download. If the content
                // is new, we activate the new bundle and update the appropriate
                // clocks.
                f.lastSuccessfulRequest = now
                f.lastSuccessfulDownload = now
                f.etag = etag ?? ""
                f.size = size
                f.type = "snapshot"
                f.clearError()
                if live[name]?.bundle != bundle {
                    live[name] = Live(
                        bundle: bundle,
                        revision: bundle.manifest.revision,
                        lastSuccessfulActivation: now)
                    bundles[name] = bundle
                    generation &+= 1
                    activated = true
                }

            case .notModified(let etag):
                // Bundle source confirms we have the latest bundle. Update the
                // request clock, leave the others alone. ETag can change
                // (RFC 7232), so we update that if needed.
                f.lastSuccessfulRequest = now
                if let etag, !etag.isEmpty { f.etag = etag }
                if live[name] == nil {
                    // Defensive: a 304 with nothing active should not happen
                    // (If-None-Match is only sent after a success). Record it
                    // rather than silently succeeding.
                    f.recordError(
                        from: BundleFetchError(
                            code: .bundleLoadError,
                            message: "Source returned 304 Not Modified, but no bundle is active.",
                            httpStatus: 304))
                } else {
                    f.clearError()
                }

            case .failed(let error):
                // A failed poll records its error into `fetch` and leaves `live`,
                // `bundles`, and `generation` untouched, so the last-known-good
                // bundle stays enforced.
                f.recordError(from: error)
            }

            fetch[name] = f
            return activated
        }

        /// Removes the named bundles entirely. Bumps `generation` only when an
        /// active (live) entry was dropped. Returns `true` when anything was
        /// removed.
        @discardableResult
        mutating func remove(_ names: Set<String>) -> Bool {
            var removedAny = false
            var activeChanged = false
            for name in names {
                if live.removeValue(forKey: name) != nil {
                    bundles.removeValue(forKey: name)
                    activeChanged = true
                    removedAny = true
                }
                if fetch.removeValue(forKey: name) != nil {
                    removedAny = true
                }
            }
            if activeChanged {
                generation &+= 1
            }
            return removedAny
        }

        /// Snapshot of every configured bundle's status plus the actual
        /// `OPA.Bundle` values for each.
        func activeBundles() -> [String: OPA.BundleStatus] {
            var out: [String: OPA.BundleStatus] = [:]
            let names = Set(live.keys).union(fetch.keys)
            out.reserveCapacity(names.count)
            for name in names {
                out[name] = OPA.BundleStatus(
                    metadata: metadata(for: name), bundle: live[name]?.bundle)
            }
            return out
        }

        /// Snapshot of every configured bundle's status metadata. For this info
        /// plus the bundle contents, see ``activeBundles``.
        func activeBundleMetadata() -> [String: OPA.BundleStatusMetadata] {
            var out: [String: OPA.BundleStatusMetadata] = [:]
            let names = Set(live.keys).union(fetch.keys)
            out.reserveCapacity(names.count)
            for name in names {
                out[name] = metadata(for: name)
            }
            return out
        }

        private func metadata(for name: String) -> OPA.BundleStatusMetadata {
            let f = fetch[name]
            let l = live[name]
            let etag = f?.etag
            return OPA.BundleStatusMetadata(
                name: name,
                activeRevision: l?.revision ?? "",
                etag: (etag?.isEmpty ?? true) ? nil : etag,
                size: f?.size,
                type: f?.type,
                lastRequest: f?.lastRequest,
                lastSuccessfulRequest: f?.lastSuccessfulRequest,
                lastSuccessfulDownload: f?.lastSuccessfulDownload,
                lastSuccessfulActivation: l?.lastSuccessfulActivation,
                code: f?.code,
                message: f?.message,
                httpCode: f?.httpCode,
                errors: f?.errors)
        }
    }
}
