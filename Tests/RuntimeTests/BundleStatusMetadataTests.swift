import Foundation
import Rego
import Testing

@testable import Runtime

// Codable behavior of the OPA Status API `"bundles"` metadata shape.

@Suite("BundleStatusMetadata Codable")
struct BundleStatusMetadataTests {
    @Test("decodes the OPA Status API bundle shape (snake_case keys, ISO8601 dates)")
    func decodesOPAShape() throws {
        let json = """
            {
              "name": "authz",
              "active_revision": "rev-1",
              "etag": "\\"e1\\"",
              "size": 2048,
              "type": "snapshot",
              "last_request": "2018-01-01T00:00:01.500Z",
              "last_successful_request": "2018-01-01T00:00:01.000Z",
              "last_successful_download": "2018-01-01T00:00:00.500Z",
              "last_successful_activation": "2018-01-01T00:00:00.000Z",
              "code": "bundle_error",
              "message": "boom",
              "http_code": 503,
              "errors": ["boom detail"]
            }
            """
        let meta = try JSONDecoder().decode(OPA.BundleStatusMetadata.self, from: Data(json.utf8))
        #expect(meta.name == "authz")
        #expect(meta.activeRevision == "rev-1")
        #expect(meta.etag == "\"e1\"")
        #expect(meta.size == 2048)
        #expect(meta.type == "snapshot")
        #expect(meta.code == "bundle_error")
        #expect(meta.message == "boom")
        #expect(meta.httpCode == 503)
        #expect(meta.errors?.map(\.message) == ["boom detail"])
        // The request clock is after the activation clock, per OPA's ordering.
        #expect(meta.lastRequest != nil)
        #expect(meta.lastSuccessfulActivation != nil)
        #expect(meta.lastRequest! > meta.lastSuccessfulActivation!)
    }

    @Test("encodes snake_case keys, ISO8601 date strings, and errors as strings")
    func encodesOPAShape() throws {
        let meta = OPA.BundleStatusMetadata(
            name: "authz",
            activeRevision: "rev-1",
            etag: "\"e1\"",
            size: 2048,
            type: "snapshot",
            lastRequest: Date(timeIntervalSince1970: 1_514_764_801),
            lastSuccessfulRequest: Date(timeIntervalSince1970: 1_514_764_800),
            lastSuccessfulDownload: Date(timeIntervalSince1970: 1_514_764_800),
            lastSuccessfulActivation: Date(timeIntervalSince1970: 1_514_764_800),
            code: "bundle_error",
            message: "boom",
            httpCode: 503,
            errors: [OPA.StatusError(message: "boom detail")])

        let data = try JSONEncoder().encode(meta)
        let obj = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])

        #expect(obj["active_revision"] as? String == "rev-1")
        #expect(obj["http_code"] as? Int == 503)
        #expect(obj["errors"] as? [String] == ["boom detail"])
        let lastRequest = obj["last_request"] as? String
        #expect(lastRequest?.contains("T") == true)
        #expect(lastRequest?.hasSuffix("Z") == true)
    }

    @Test("round-trips through encode/decode")
    func roundTrips() throws {
        // Build via decode so the dates land on exact ISO8601 fractional-second
        // values, making the equality check robust.
        let json = """
            {"name":"b","active_revision":"r","last_request":"2020-05-01T12:00:00.250Z",
             "last_successful_download":"2020-05-01T11:59:59.000Z","http_code":404,
             "code":"bundle_error","errors":["a","b"]}
            """
        let original = try JSONDecoder().decode(OPA.BundleStatusMetadata.self, from: Data(json.utf8))
        let data = try JSONEncoder().encode(original)
        let round = try JSONDecoder().decode(OPA.BundleStatusMetadata.self, from: data)
        #expect(round == original)
    }

    @Test("omits empty active_revision and nil fields on encode")
    func omitsEmptyFields() throws {
        let meta = OPA.BundleStatusMetadata(name: "b")

        let data = try JSONEncoder().encode(meta)
        let obj = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])

        #expect(obj["name"] as? String == "b")
        #expect(obj["active_revision"] == nil)
        #expect(obj["code"] == nil)
        #expect(obj["errors"] == nil)
        #expect(obj["etag"] == nil)
    }

    @Test("a BundleFetchError's httpStatus maps into http_code via the store")
    func errorExtractionMapsHTTPStatus() {
        var store = OPA.BundleStore()
        let err = BundleFetchError(code: .bundleLoadError, message: "429!", httpStatus: 429, host: "h")

        _ = store.update(name: "x", .failed(err), now: Date())

        let meta = store.activeBundleMetadata()["x"]
        #expect(meta?.code == "bundleLoadError")
        #expect(meta?.httpCode == 429)
        #expect(meta?.message == "429!")
    }
}
