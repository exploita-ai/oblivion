import path from "node:path"

const targets = [
  { target: "bun-darwin-arm64", platform: "darwin", arch: "arm64", executable: "oblivion-manager", launcher: "oblivion", nativePackage: "@opentui/core-darwin-arm64", nativeLibrary: "libopentui.dylib" },
  { target: "bun-linux-arm64", platform: "linux", arch: "arm64", executable: "oblivion-manager", launcher: "oblivion", nativePackage: "@opentui/core-linux-arm64", nativeLibrary: "libopentui.so" },
  { target: "bun-linux-x64", platform: "linux", arch: "x64", executable: "oblivion-manager", launcher: "oblivion", nativePackage: "@opentui/core-linux-x64", nativeLibrary: "libopentui.so" },
  { target: "bun-windows-x64", platform: "win32", arch: "x64", executable: "oblivion-manager.exe", launcher: "oblivion.exe", nativePackage: "@opentui/core-win32-x64", nativeLibrary: "opentui.dll" },
] as const

export type ManagerTarget = typeof targets[number]

export function managerTarget(target: string) {
  const descriptor = targets.find((descriptor) => descriptor.target === target)
  if (!descriptor) throw new Error("Unsupported manager target")
  return descriptor
}

export function systemManagerTarget(platform: string = process.platform, arch: string = process.arch) {
  return managerTarget(`bun-${platform === "win32" ? "windows" : platform}-${arch}`)
}

export function managerLauncherPath(executable: string, descriptor: ManagerTarget) {
  const paths = descriptor.platform === "win32" ? path.win32 : path.posix
  return paths.join(paths.dirname(executable), descriptor.launcher)
}
