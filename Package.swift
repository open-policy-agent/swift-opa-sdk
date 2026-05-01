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
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.81.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.30.0"),
        .package(url: "https://github.com/swift-server/async-http-client", from: "1.21.0"),
        // TODO: Swap for whatever our solution ends up being. This is not the most recent commit,
        // but it is the last one that supports macOS 13 as a target.
        // Placeholder until we decide how to handle tar.gz wrangling:
        .package(
            url: "https://github.com/tsolomko/SWCompression", revision: "5b57ac0fcd78ccd9f42644a4cf7a379ec3821ef1"),
        .package(url: "https://github.com/jpsim/Yams", from: "6.2.1"),
    ],
    targets: [
        .target(
            name: "SwiftOPASDK",
            dependencies: [
                .product(name: "SwiftOPA", package: "swift-opa"),
                .product(name: "Yams", package: "Yams"),
                "Config",
                "RegoExtensions",
                "Runtime",
            ]
        ),
        .target(
            name: "Config",
            dependencies: [
                .product(name: "SwiftOPA", package: "swift-opa")
            ],
            path: "Sources/Config"
        ),
        .target(
            name: "RegoExtensions",
            dependencies: [
                .product(name: "SwiftOPA", package: "swift-opa"),
                .product(name: "Yams", package: "Yams"),
            ],
            path: "Sources/RegoExtensions"
        ),
        .target(
            name: "Runtime",
            dependencies: [
                "Config",
                "RegoExtensions",
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "SwiftOPA", package: "swift-opa"),
                .product(name: "SWCompression", package: "SWCompression"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Yams", package: "Yams"),
            ],
            path: "Sources/Runtime"
        ),
        .testTarget(
            name: "SwiftOPASDKTests",
            dependencies: ["SwiftOPASDK"]
        ),
        .testTarget(
            name: "ConfigTests",
            dependencies: ["Config"]
        ),
        .testTarget(
            name: "RegoExtensionTests",
            dependencies: ["RegoExtensions"]
        ),
        .testTarget(
            name: "RuntimeTests",
            dependencies: [
                "Runtime",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
            ]
        ),
    ]
)
