# Swift-OPA-SDK

[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fopen-policy-agent%2Fswift-opa-sdk%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/open-policy-agent/swift-opa-sdk) [![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fopen-policy-agent%2Fswift-opa-sdk%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/open-policy-agent/swift-opa-sdk)

Swift-OPA-SDK is a Swift package that extends [Swift OPA](https://github.com/open-policy-agent/swift-opa) with a higher-level interface and extended features.

## Adding Swift-OPA-SDK as a Dependency

**Package.swift**
```swift
let package = Package(
    // required minimum versions for using swift-opa-sdk
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
    ],
    // name, platforms, products, etc.
    dependencies: [
        .package(url: "https://github.com/open-policy-agent/swift-opa-sdk", branch: "main"),
        // other dependencies
    ],
    targets: [
        // or libraryTarget
        .executableTarget(name: "<target-name>", dependencies: [
            .product(name:"SwiftOPASDK", package: "swift-opa-sdk"),
            // other dependencies
        ]),
        // other targets
    ]
)
```

## Usage

The core of the Swift OPA SDK is the `OPA.Runtime` type.
It represents an instance of a Rego policy engine, and can be started with several options that control configuration, logging, and lifecycle.

The Runtime is intended to provide a "policy decision point (PDP) in a box", and is meant to be embedded into larger Swift applications.
Once configured, the Runtime will automatically handle applying updates to the underlying policy and data stores as needed.

Here's a basic usage example (assumes you already have a valid OPA config and policy bundles available):

```swift
import Yams // https://github.com/jpsim/Yams
import Foundation
import SwiftOPASDK

// Fetch config from YAML file on-disk.
let configURL = URL(fileURLWithPath: "config.yaml", relativeTo: URL(fileURLWithPath: FileManager.default.currentDirectoryPath))
let config = try YAMLDecoder().decode(OPA.Config.self, from: Data(contentsOf: configURL))

// Start the runtime, and launch its background worker tasks.
let runtime = try OPA.Runtime(config: config)
let runtimeTask = Task { try await runtime.run() }

// Make policy decisions at any time while run() is active.
let result = try await runtime.decision("authz/allow", input: myInput)

// Shut down when done.
runtimeTask.cancel()
```

Its APIs are inspired by OPA's [`sdk.OPA` type](https://pkg.go.dev/github.com/open-policy-agent/opa/v1/sdk#OPA) in the Go [`sdk` library](https://pkg.go.dev/github.com/open-policy-agent/opa/v1/sdk).

## RegoExtensions

The `RegoExtensions` target is the home for built-in Rego functions this SDK provides on top of
[swift-opa](https://github.com/open-policy-agent/swift-opa). It currently ships no builtins of its
own, and `SDKBuiltinFuncs.sdkDefaultBuiltins` returns an empty set.

### Adding RegoExtensions as a dependency

**Package.swift**
```swift
let package = Package(
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
    ],
    dependencies: [
        .package(url: "https://github.com/open-policy-agent/swift-opa", branch: "main"),
        .package(url: "https://github.com/open-policy-agent/swift-opa-sdk", branch: "main"),
    ],
    targets: [
        .executableTarget(name: "<target-name>", dependencies: [
            .product(name: "SwiftOPA", package: "swift-opa"),
            .product(name: "RegoExtensions", package: "swift-opa-sdk"),
        ]),
    ]
)
```

### Example: registering your own custom builtins

If you use `OPA.Engine` directly, register any custom builtins via the `customBuiltins`
parameter. You can merge `SDKBuiltinFuncs.sdkDefaultBuiltins` (currently empty) in as well so
your code keeps picking up SDK builtins if any are added later:

```swift
import Rego
import RegoExtensions

let myBuiltins: [String: AsyncBuiltin] = [
    "custom.greet": { _, args in
        guard case .string(let name) = args.first else {
            throw BuiltinError.argumentTypeMismatch(arg: "name", got: args.first?.typeName ?? "none", want: "string")
        }
        return .string("Hello, \(name)!")
    }
]

let engine = OPA.Engine(
    bundlePaths: [.init(path: "./bundles/authz.tar.gz", isDir: false)],
    customBuiltins: SDKBuiltinFuncs.sdkDefaultBuiltins.merging(myBuiltins, uniquingKeysWith: { _, new in new })
)
```

## Bundle Service Support

Currently, the `OPA.Runtime` only implements loading bundles from a subset of the control plane [`service` credential types](https://www.openpolicyagent.org/docs/configuration#services) that OPA supports.

| Type | Config Prefix | Supported? |
|:---|:---|:---:|
| No Auth (default) | - | :white_check_mark: |
| [Bearer Token](https://www.openpolicyagent.org/docs/configuration#bearer-token) | `services[_].credentials.bearer` | :white_check_mark: |
| [Client TLS Certificate](https://www.openpolicyagent.org/docs/configuration#client-tls-certificate) | `services[_].credentials.client_tls` | :white_check_mark: |
| [OAuth2 Client Credentials](https://www.openpolicyagent.org/docs/configuration#oauth2-client-credentials) | `services[_].credentials.oauth2` | :white_check_mark: |
| [OAuth2 Client Credentials JWT authentication](https://www.openpolicyagent.org/docs/configuration#oauth2-client-credentials-jwt-authentication) | `services[_].credentials.oauth2` | :x: |
| [OAuth2 JWT Bearer Grant Type](https://www.openpolicyagent.org/docs/configuration#oauth2-jwt-bearer-grant-type) | `services[_].credentials.oauth2` | :x: |
| [AWS Signature](https://www.openpolicyagent.org/docs/configuration#aws-signature) | `services[_].credentials.s3_signing` | :x: |
| [GCP Metadata Token](https://www.openpolicyagent.org/docs/configuration#gcp-metadata-token) | `services[_].credentials.gcp_metadata` | :x: |
| [Azure Managed Identities Token](https://www.openpolicyagent.org/docs/configuration#azure-managed-identities-token) | `services[_].credentials.azure_managed_identity` | :x: |
| [OCI Repositories](https://www.openpolicyagent.org/docs/configuration#oci-repositories) | - | :x: |
| [Custom Plugin](https://www.openpolicyagent.org/docs/configuration#custom-plugin) | `services[_].credentials.plugin` | :white_check_mark: |

Note: Custom Plugin support is available by providing a custom `BundleLoader` type at `OPA.Runtime` init.

## Version Support

We aim to support "latest Swift major version - 2" releases back. As an example, for Swift 6.4, that implies supporting Swift 6.3, and 6.2 as well.

For `.macOS` and `.iOS` platform versions, we aim to support the platform versions associated with the current and previous major macOS releases. For example, if the current macOS release is macOS 26 "Tahoe", then the previous major release was macOS 15 "Sequoia", and we would support the `.macOS(.v15)` target, as well as the iOS version that released at the same time, `.iOS(.v18)`.

## Community Support

Feel free to open an issue if you encounter any problems using swift-opa-sdk, or have ideas on how to make it even better.
We are also happy to answer more general questions in the `#swift-opa` channel of the
[OPA Slack](https://slack.openpolicyagent.org/).
