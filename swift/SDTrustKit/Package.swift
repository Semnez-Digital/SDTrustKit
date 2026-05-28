// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SDTrustKit",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "SDTrustKit",
            targets: ["SDTrustKit"]
        )
    ],
    targets: [
        .target(name: "SDTrustKit"),
        .testTarget(
            name: "SDTrustKitTests",
            dependencies: ["SDTrustKit"]
        ),
    ]
)
