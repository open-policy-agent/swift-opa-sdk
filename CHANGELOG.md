# Change Log

All notable changes to this project will be documented in this file. This
project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased

### Swift OPA SDK Runtime

The `SwiftOPASDK` library provides a high-level OPA policy runtime built on top of the [swift-opa](https://github.com/open-policy-agent/swift-opa) evaluator.
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
by default, using the Yams library.
