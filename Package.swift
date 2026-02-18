// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "swift-opa-sdk",
    products: [
        .library(
            name: "SwiftOPASDK",
            targets: ["SwiftOPASDK"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/open-policy-agent/swift-opa", branch: "main")
    ],
    targets: [
        .target(
            name: "SwiftOPASDK"
        ),
        .testTarget(
            name: "SwiftOPASDKTests",
            dependencies: ["SwiftOPASDK"]
        ),
    ]
)
