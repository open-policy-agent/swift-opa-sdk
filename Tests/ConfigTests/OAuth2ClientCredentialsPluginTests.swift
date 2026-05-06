import Foundation
import Rego
import Testing

@testable import Config

@Suite("OAuth2ClientCredentialsPluginTests")
struct OAuth2ClientCredentialsPluginTests {

    // MARK: - Valid Cases

    struct ValidTestCase: Sendable {
        let description: String
        let json: String
        let expectedScopes: [String]?
        let expectedAdditionalHeaders: [String: String]?
        let expectedAdditionalParameters: [String: String]?
    }

    static var validTestCases: [ValidTestCase] {
        [
            ValidTestCase(
                description: "minimal valid config",
                json: #"""
                    {
                      "token_url": "https://example.com/oauth2/token",
                      "client_id": "my-client",
                      "client_secret": "my-secret"
                    }
                    """#,
                expectedScopes: nil,
                expectedAdditionalHeaders: nil,
                expectedAdditionalParameters: nil
            ),
            ValidTestCase(
                description: "with explicit grant_type=client_credentials",
                json: #"""
                    {
                      "token_url": "https://example.com/oauth2/token",
                      "client_id": "my-client",
                      "client_secret": "my-secret",
                      "grant_type": "client_credentials"
                    }
                    """#,
                expectedScopes: nil,
                expectedAdditionalHeaders: nil,
                expectedAdditionalParameters: nil
            ),
            ValidTestCase(
                description: "with scopes",
                json: #"""
                    {
                      "token_url": "https://example.com/oauth2/token",
                      "client_id": "my-client",
                      "client_secret": "my-secret",
                      "scopes": ["read:bundles", "read:data"]
                    }
                    """#,
                expectedScopes: ["read:bundles", "read:data"],
                expectedAdditionalHeaders: nil,
                expectedAdditionalParameters: nil
            ),
            ValidTestCase(
                description: "with additional_headers",
                json: #"""
                    {
                      "token_url": "https://example.com/oauth2/token",
                      "client_id": "my-client",
                      "client_secret": "my-secret",
                      "additional_headers": {"X-Request-ID": "abc123"}
                    }
                    """#,
                expectedScopes: nil,
                expectedAdditionalHeaders: ["X-Request-ID": "abc123"],
                expectedAdditionalParameters: nil
            ),
            ValidTestCase(
                description: "with additional_parameters (e.g. audience for Auth0)",
                json: #"""
                    {
                      "token_url": "https://example.com/oauth2/token",
                      "client_id": "my-client",
                      "client_secret": "my-secret",
                      "additional_parameters": {"audience": "https://api.example.com"}
                    }
                    """#,
                expectedScopes: nil,
                expectedAdditionalHeaders: nil,
                expectedAdditionalParameters: ["audience": "https://api.example.com"]
            ),
        ]
    }

    @Test(arguments: validTestCases)
    func testValid(tc: ValidTestCase) throws {
        let data = tc.json.data(using: .utf8)!
        let plugin = try JSONDecoder().decode(OPA.OAuth2ClientCredentialsPlugin.self, from: data)
        #expect(plugin.tokenURL == "https://example.com/oauth2/token")
        #expect(plugin.clientID == "my-client")
        #expect(plugin.clientSecret == "my-secret")
        #expect(plugin.grantType == "client_credentials")
        #expect(plugin.scopes == tc.expectedScopes)
        #expect(plugin.additionalHeaders == tc.expectedAdditionalHeaders)
        #expect(plugin.additionalParameters == tc.expectedAdditionalParameters)
    }

    // MARK: - Invalid Cases

    struct InvalidTestCase: Sendable {
        let description: String
        let json: String
    }

    static var invalidTestCases: [InvalidTestCase] {
        [
            InvalidTestCase(
                description: "missing token_url",
                json: #"""
                    {
                      "client_id": "my-client",
                      "client_secret": "my-secret"
                    }
                    """#
            ),
            InvalidTestCase(
                description: "empty token_url",
                json: #"""
                    {
                      "token_url": "",
                      "client_id": "my-client",
                      "client_secret": "my-secret"
                    }
                    """#
            ),
            InvalidTestCase(
                description: "token_url not https",
                json: #"""
                    {
                      "token_url": "http://example.com/oauth2/token",
                      "client_id": "my-client",
                      "client_secret": "my-secret"
                    }
                    """#
            ),
            InvalidTestCase(
                description: "missing client_id",
                json: #"""
                    {
                      "token_url": "https://example.com/oauth2/token",
                      "client_secret": "my-secret"
                    }
                    """#
            ),
            InvalidTestCase(
                description: "empty client_id",
                json: #"""
                    {
                      "token_url": "https://example.com/oauth2/token",
                      "client_id": "",
                      "client_secret": "my-secret"
                    }
                    """#
            ),
            InvalidTestCase(
                description: "missing client_secret",
                json: #"""
                    {
                      "token_url": "https://example.com/oauth2/token",
                      "client_id": "my-client"
                    }
                    """#
            ),
            InvalidTestCase(
                description: "empty client_secret",
                json: #"""
                    {
                      "token_url": "https://example.com/oauth2/token",
                      "client_id": "my-client",
                      "client_secret": ""
                    }
                    """#
            ),
            InvalidTestCase(
                description: "unsupported grant_type=jwt_bearer",
                json: #"""
                    {
                      "token_url": "https://example.com/oauth2/token",
                      "client_id": "my-client",
                      "client_secret": "my-secret",
                      "grant_type": "jwt_bearer"
                    }
                    """#
            ),
        ]
    }

    @Test(arguments: invalidTestCases)
    func testInvalid(tc: InvalidTestCase) throws {
        let data = tc.json.data(using: .utf8)!
        #expect(throws: (any Error).self) {
            _ = try JSONDecoder().decode(OPA.OAuth2ClientCredentialsPlugin.self, from: data)
        }
    }
}

// MARK: - Type Extensions

extension OAuth2ClientCredentialsPluginTests.ValidTestCase: CustomTestStringConvertible {
    var testDescription: String { description }
}

extension OAuth2ClientCredentialsPluginTests.InvalidTestCase: CustomTestStringConvertible {
    var testDescription: String { description }
}
