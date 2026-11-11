// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OblivionNative",
    platforms: [.macOS("15.0")],
    products: [.executable(name: "oblivion-vm", targets: ["OblivionVM"])],
    targets: [
        .target(name: "RuntimeLifetime"),
        .executableTarget(name: "OblivionVM", dependencies: ["RuntimeLifetime"]),
        .testTarget(name: "RuntimeLifetimeTests", dependencies: ["RuntimeLifetime"]),
    ]
)
