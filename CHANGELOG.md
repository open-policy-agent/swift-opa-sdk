# Change Log

All notable changes to this project will be documented in this file. This
project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased

### Swift OPA SDK Runtime

The `SwiftOPASDK` library provides a high-level, production-ready OPA policy
runtime built on top of the [swift-opa](https://github.com/open-policy-agent/swift-opa)
evaluator. The `Runtime` type manages the full lifecycle of an OPA agent:
loading bundles, refreshing them on schedule, applying configuration, and
exposing a simple evaluation interface to callers.

### Config management (#15, #16)

The SDK parses and validates OPA's `config.yaml` format, providing Swift types
for the full configuration schema (services, bundle sources, discovery,
decision logs). The config layer enforces required fields, fills in sensible
defaults, and surfaces descriptive errors for invalid configurations.

### Bundle loading: HTTP sources (#17, #19, #26, #27)

The `Runtime` supports loading bundles from HTTP/HTTPS bundle sources declared
in OPA configuration:

- Parallel bundle fetch from multiple configured sources
- Conditional fetch via `ETag` / `If-None-Match` to avoid redundant downloads
- Long-polling support for push-based bundle delivery
- `ClientTLS` bundle loader with mutual TLS authentication
- OAuth2 client-credentials flow and Bearer token authentication for
  authenticated bundle endpoints

### Discovery (#20, #28, #29)

Swift OPA SDK implements OPA's
[Discovery API](https://www.openpolicyagent.org/docs/management-discovery) as
a `ConfigProvider`. The Runtime can bootstrap its full configuration by
evaluating a discovery bundle, then activate the resulting config and start
fetching downstream bundles — mirroring OPA's own discovery flow.

Discovery support includes:

- Data-only bundles during Discovery evaluation (#28)
- Bugfixes for config merging edge cases discovered during Discovery testing (#29)

### RegoExtensions: custom builtin support (#8, #25, #35, #37)

The `RegoExtensions` library target allows callers to extend the OPA evaluator
with custom builtin functions implemented in Swift. The SDK ships YAML
encoding/decoding builtins (`yaml.marshal`, `yaml.unmarshal`, `yaml.is_valid`)
by default, using the Yams library.

The builtin extension API supports both synchronous and asynchronous custom
builtins, following the same sync/async dispatch model used internally by
swift-opa (#37).

The `RegoExtensions` target is exposed as a standalone library product so that
downstream packages can declare a focused dependency on just the extension
API without pulling in the full Runtime (#35).

### MiniPlanner: data-only queries (#31)

A `MiniPlanner` component supports basic data-only OPA queries — evaluating
policies against a data document without a full IR plan. This capability was
originally developed in [swift-opa](https://github.com/open-policy-agent/swift-opa/pull/145)
and moved to the SDK (#31) where it serves as the foundation for Discovery
config evaluation.

### Documentation (#24)

Public API surface documented with doc comments throughout `SwiftOPASDK` and
`RegoExtensions` targets.

### CI and project infrastructure (#6, #9, #11, #13, #36)

- Initial project skeleton with GitHub Actions CI (#6)
- PR template (#11)
- Hardened CI workflows with [zizmor](https://github.com/zizmorcore/zizmor)
  static analysis for GitHub Actions security (#13)
- Dependabot configuration for Actions and Swift package updates
- Runner image pinning for reproducible builds across older Swift versions (#36)
