import { createSolidTransformPlugin } from "@opentui/solid/bun-plugin"
import path from "node:path"

if (`bun@${Bun.version}` !== (await Bun.file(path.resolve(import.meta.dir, "../../../package.json")).json()).packageManager) {
  throw new Error("Use the Bun version pinned by the repository to build the manager")
}
const target = process.argv.find((value) => value.startsWith("--target="))?.slice(9) ?? "bun-darwin-arm64"
if (!["bun-darwin-arm64", "bun-linux-arm64", "bun-linux-x64"].includes(target)) throw new Error("Unsupported manager target")
const output = process.argv.find((value) => value.startsWith("--output="))?.slice(9)
  ?? path.resolve(import.meta.dir, "../../..", "artifacts/oblivion-manager", target, "oblivion-manager")
const result = await Bun.build({
  entrypoints: [path.resolve(import.meta.dir, "../src/index.tsx")],
  plugins: [createSolidTransformPlugin()],
  target: "bun", format: "esm", minify: true,
  compile: { target: target as Bun.Build.CompileTarget, outfile: output, autoloadBunfig: false, autoloadDotenv: false, autoloadPackageJson: false, autoloadTsconfig: false },
  define: target.includes("linux") ? { "process.env.OPENTUI_LIBC": '"glibc"' } : {},
})
if (!result.success) throw new Error(result.logs.map(String).join("\n"))
for (const file of ["LICENSE", "PROVENANCE.md"]) {
  await Bun.write(path.join(path.dirname(output), "assets/licenses/termcn", file), Bun.file(path.resolve(import.meta.dir, "../src/vendor/termcn", file)))
}
if (target.includes("linux")) {
  const native = `@opentui/core-${target.slice(4)}`
  await Bun.write(
    path.join(path.dirname(output), "assets", native, "libopentui.so"),
    Bun.file(path.join(path.dirname(Bun.resolveSync(native, import.meta.resolve("@opentui/core"))), "libopentui.so")),
  )
}
console.log(output)
