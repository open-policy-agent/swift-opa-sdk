# Swift-OPA-SDK

[![Swift 6.0.3+](https://img.shields.io/badge/Swift-6.0.3+-blue.svg)](https://developer.apple.com/swift/)

Swift-OPA-SDK is a Swift package that extends [Swift OPA](https://github.com/open-policy-agent/swift-opa) with a higher-level interface and extended features.

## Adding Swift-OPA-SDK as a Dependency

**Package.swift**
```swift
let package = Package(
    // required minimum versions for using swift-opa-sdk
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
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

## Community Support

Feel free to open an issue if you encounter any problems using swift-opa-sdk, or have ideas on how to make it even better.
We are also happy to answer more general questions in the `#swift-opa` channel of the
[OPA Slack](https://slack.openpolicyagent.org/).
