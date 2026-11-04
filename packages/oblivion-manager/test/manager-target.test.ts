import { expect, test } from "bun:test"
import path from "node:path"
import { managerLauncherPath, managerTarget, systemManagerTarget } from "../src/manager-target"

test.each([
  { platform: "darwin", arch: "arm64", target: "bun-darwin-arm64", executable: "oblivion-manager", launcher: "oblivion", nativePackage: "@opentui/core-darwin-arm64", nativeLibrary: "libopentui.dylib" },
  { platform: "linux", arch: "arm64", target: "bun-linux-arm64", executable: "oblivion-manager", launcher: "oblivion", nativePackage: "@opentui/core-linux-arm64", nativeLibrary: "libopentui.so" },
  { platform: "linux", arch: "x64", target: "bun-linux-x64", executable: "oblivion-manager", launcher: "oblivion", nativePackage: "@opentui/core-linux-x64", nativeLibrary: "libopentui.so" },
  { platform: "win32", arch: "x64", target: "bun-windows-x64", executable: "oblivion-manager.exe", launcher: "oblivion.exe", nativePackage: "@opentui/core-win32-x64", nativeLibrary: "opentui.dll" },
] as const)("the builder default selects its exact executable and OpenTUI asset (%j)", (expected) => {
  expect(systemManagerTarget(expected.platform, expected.arch)).toEqual(expected)
  expect(managerTarget(expected.target)).toBe(systemManagerTarget(expected.platform, expected.arch))
})

test.each(["bun-windows-arm64", "bun-darwin-x64", "bun-linux-x64-musl", "windows-x64", ""])("unknown or unqualified target %j has no implicit fallback", (target) => {
  expect(() => managerTarget(target)).toThrow("Unsupported manager target")
})

test("the default target follows the actual builder system", () => {
  expect(systemManagerTarget()).toBe(systemManagerTarget(process.platform, process.arch))
})

test("launcher discovery uses the target's path rules and preserves literal spaces and shell characters", () => {
  expect(managerLauncherPath("C:\\Program Files\\Oblivion & Tools\\oblivion-manager.exe", managerTarget("bun-windows-x64"))).toBe("C:\\Program Files\\Oblivion & Tools\\oblivion.exe")
  expect(managerLauncherPath("\\\\server\\share\\Oblivion\\oblivion-manager.exe", managerTarget("bun-windows-x64"))).toBe("\\\\server\\share\\Oblivion\\oblivion.exe")
  expect(managerLauncherPath("/opt/Oblivion & Tools/oblivion-manager", managerTarget("bun-linux-x64"))).toBe("/opt/Oblivion & Tools/oblivion")
  expect(managerLauncherPath("/Applications/Oblivion/bin/oblivion-manager", managerTarget("bun-darwin-arm64"))).toBe("/Applications/Oblivion/bin/oblivion")
})

test.each([false, true])("the actual nativeLauncher consumer preserves an explicit override (%s)", async (override) => {
  const env = { ...process.env }
  delete env.OBLIVION_LAUNCHER
  if (override) env.OBLIVION_LAUNCHER = "C:\\Explicit path & tools\\oblivion.exe"
  const child = Bun.spawn([process.execPath, "--eval", `import { nativeLauncher } from ${JSON.stringify(import.meta.resolve("../src/native-control"))}; console.log(nativeLauncher())`],
    { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const [output, error] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text()])
  expect(error).toBe("")
  expect(await child.exited).toBe(0)
  expect(output.trimEnd()).toBe(override ? env.OBLIVION_LAUNCHER! : path.join(path.dirname(process.execPath), process.platform === "win32" ? "oblivion.exe" : "oblivion"))
})
