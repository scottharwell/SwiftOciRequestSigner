// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftOCIRequestSigner",
    platforms: [
        .macOS(.v10_14), .iOS(.v12),
    ],
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "SwiftOCIRequestSigner",
            targets: ["SwiftOCIRequestSigner"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url: "https://github.com/IBM-Swift/BlueRSA.git", from: "1.0.34"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.1.2")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "SwiftOCIRequestSigner",
            dependencies: [],
            path: "OCIRequestSigner"),
        .testTarget(
            name: "Swift OCI Request Signer Tests",
            dependencies: ["SwiftOCIRequestSigner"],
            path: "OciRequestSignerTests"),
    ]
)
