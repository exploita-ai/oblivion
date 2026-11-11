import { createSolidTransformPlugin } from "@opentui/solid/bun-plugin"
import path from "node:path"
import { managerTarget, systemManagerTarget } from "../src/manager-target"

if (`bun@${Bun.version}` !== (await Bun.file(path.resolve(import.meta.dir, "../../../package.json")).json()).packageManager) {
  throw new Error("Use the Bun version pinned by the repository to build the manager")
}
const selected = process.argv.find((value) => value.startsWith("--target="))?.slice(9)
const descriptor = selected === undefined ? systemManagerTarget() : managerTarget(selected)
const output = process.argv.find((value) => value.startsWith("--output="))?.slice(9)
  ?? path.resolve(import.meta.dir, "../../..", "artifacts/oblivion-manager", descriptor.target, descriptor.executable)
if (descriptor.platform === "win32" && !output.endsWith(".exe")) throw new Error("Windows manager output must end in .exe")
const result = await Bun.build({
  entrypoints: [path.resolve(import.meta.dir, "../src/index.tsx")],
  plugins: [createSolidTransformPlugin()],
  target: "bun", format: "esm", minify: true,
  compile: { target: descriptor.target, outfile: output, autoloadBunfig: false, autoloadDotenv: false, autoloadPackageJson: false, autoloadTsconfig: false },
  define: descriptor.platform === "linux" ? { "process.env.OPENTUI_LIBC": '"glibc"' } : {},
})
if (!result.success) throw new Error(result.logs.map(String).join("\n"))
for (const file of ["LICENSE", "NOTICE"]) {
  await Bun.write(path.join(path.dirname(output), "assets/licenses/oblivion", file), Bun.file(path.resolve(import.meta.dir, "../../..", file)))
}
for (const file of ["LICENSE", "PROVENANCE.md"]) {
  await Bun.write(path.join(path.dirname(output), "assets/licenses/termcn", file), Bun.file(path.resolve(import.meta.dir, "../src/vendor/termcn", file)))
}
await Bun.write(
  path.join(path.dirname(output), "assets/licenses/shell-quote/LICENSE"),
  Bun.file(path.join(path.dirname(Bun.resolveSync("shell-quote/package.json", import.meta.dir)), "LICENSE")),
)
await Bun.write(
  path.join(path.dirname(output), "assets", descriptor.nativePackage, descriptor.nativeLibrary),
  Bun.file(path.join(path.dirname(Bun.resolveSync(descriptor.nativePackage, import.meta.resolve("@opentui/core"))), descriptor.nativeLibrary)),
)
console.log(output)
