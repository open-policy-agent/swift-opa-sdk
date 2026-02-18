// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "swift-opa-sdk",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(
            name: "SwiftOPASDK",
            targets: ["SwiftOPASDK"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/open-policy-agent/swift-opa", branch: "main"),
        .package(url: "https://github.com/jpsim/Yams", from: "6.2.1"),
    ],
    targets: [
        .target(
            name: "SwiftOPASDK",
            dependencies: [
                .product(name: "SwiftOPA", package: "swift-opa"),
                .product(name: "Yams", package: "Yams"),
            ]
        ),
        .testTarget(
            name: "SwiftOPASDKTests",
            dependencies: ["SwiftOPASDK"]
        ),
        .testTarget(
            name: "RegoExtensionTests",
            dependencies: ["SwiftOPASDK"]
        ),
    ]
)
