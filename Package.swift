// swift-tools-version:6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "FlyFunCommon",
    platforms: [
        .macOS(.v26), .iOS("18.6")
    ],
    products: [
        .library(
            name: "FlyFunCommon",
            targets: ["FlyFunCommon"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/roznet/rzutils", from: "1.0.31"),
    ],
    targets: [
        .target(
            name: "FlyFunCommon",
            dependencies: [
                .product(name: "RZUtilsSwift", package: "rzutils"),
            ]
        ),
        .testTarget(
            name: "FlyFunCommonTests",
            dependencies: ["FlyFunCommon"]
        ),
    ]
)
