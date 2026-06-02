// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SDTrustKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "SDTrustKit",
            targets: ["SDTrustKit"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "CSDTrustKit",
            path: "swift/SDTrustKit/Frameworks/CSDTrustKit.xcframework"
        ),
        .target(
            name: "SDTrustKit",
            dependencies: ["CSDTrustKit"],
            path: "swift/SDTrustKit/Sources/SDTrustKit",
            swiftSettings: [
                .define("SD_TRUST_KIT_STATIC")
            ]
        ),
        .testTarget(
            name: "SDTrustKitTests",
            dependencies: ["SDTrustKit"],
            path: "swift/SDTrustKit/Tests/SDTrustKitTests"
        ),
    ]
)
