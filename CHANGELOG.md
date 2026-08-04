# Change Log

All notable changes to this project will be documented in this file. This
project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased

### Breaking API changes

The `httpClientConfig:` parameter on `OPA.Runtime.init`, `OPA.DiscoveryConfigProvider.init`, `OPA.RESTClientBundleLoader.init`, and the `OPA.HTTPBundleLoader` protocol requirements changed type from `HTTPClient.Configuration?` to the new `OPA.HTTPClientConfigSource?` type.

If you were using that parameter previously with a config value, you can wrap it with the `.fixed` enum case constructor: `httpClientConfig: .fixed(myConfiguration)`.

### Bundle loading: closure-based HTTP client / TLS configuration

`OPA.HTTPClientConfigSource` supports two ways to use closures to control your TLS or HTTPClient configuration:

- `.tls(OPA.TLSConfigurationProvider)`: `@Sendable () async throws -> TLSConfiguration`.
  The result becomes the `tlsConfiguration` value of the global default HTTP client config that the loader will use.
- `.configuration(OPA.HTTPClientConfigurationProvider)`: `@Sendable () async throws -> HTTPClient.Configuration`.
  Supplies the whole configuration the loader should use.

This makes rotating mTLS identities much easier: before this change, TLS material could only be supplied as a fixed value at construction, or read from cert/key file paths on disk via `credentials.client_tls`.

Other notes:

- TLS/Config results are used verbatim.
- If the TLS/Config provider closure throws, that `load()` call will fail, and be retried later.
- If using closure config sources, that closure owns all TLS configuration for the Runtime.
- The OAuth2 token request still builds its own `HTTPClient` from the global default http client config, so it cannot be configured this way yet.

## 0.0.1
### Swift OPA SDK Runtime

The `SwiftOPASDK` library provides a high-level OPA policy runtime built on top of the [swift-opa](https://github.com/open-policy-agent/swift-opa) [Rego IR](https://www.openpolicyagent.org/docs/ir) evaluator.
The `Runtime` type manages the full lifecycle of an OPA agent: loading bundles, refreshing them on schedule, applying configuration updates through the [Discovery API](https://www.openpolicyagent.org/docs/management-discovery), and exposing a simple evaluation interface to callers.

### Config management

The SDK provides types for parsing and validating OPA's `config.yaml` format.
The config types enforce required fields, fill in the same defaults as OPA, and provides descriptive errors for invalid configurations.

### Bundle loading: HTTP sources

The `Runtime` type supports loading bundles from HTTP/HTTPS bundle sources declared
in OPA configs.

It supports parallel bundle fetching from multiple configured sources, as well as the `ETag` and `If-None-Match` header system to avoid redundant downloads.
Long-polling is also supported.

The only supported authentication methods at this time are:
 - [Bearer auth](https://www.openpolicyagent.org/docs/configuration#bearer-token)
 - [Basic OAuth2 auth](https://www.openpolicyagent.org/docs/configuration#oauth2-client-credentials)
 - [ClientTLS auth](https://www.openpolicyagent.org/docs/configuration#client-tls-certificate)

### Discovery

The Swift OPA SDK implements OPA's [Discovery API](https://www.openpolicyagent.org/docs/management-discovery) as a `ConfigProvider` type.
This allows a Runtime instance to start with a minimal bootstrap configuration, and then fetch down the full configuration from a remote server at runtime.

### RegoExtensions: custom builtin support

The `RegoExtensions` library target allows callers to extend the OPA evaluator
with custom builtin functions implemented in Swift. The SDK ships YAML
encoding/decoding builtins (`yaml.marshal`, `yaml.unmarshal`, `yaml.is_valid`)
by default, using the [Yams](https://github.com/jpsim/Yams) library.
