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
            path: "Frameworks/CSDTrustKit.xcframework"
        ),
        .target(
            name: "SDTrustKit",
            dependencies: ["CSDTrustKit"],
            swiftSettings: [
                .define("SD_TRUST_KIT_STATIC")
            ]
        ),
        .testTarget(
            name: "SDTrustKitTests",
            dependencies: ["SDTrustKit"]
        ),
    ]
)
