import path from "node:path"

const output = path.resolve(import.meta.dir, "../dist/server.mjs")
const result = await Bun.build({
  entrypoints: [path.resolve(import.meta.dir, "../src/index.ts")],
  target: "node", format: "esm", minify: true,
  outdir: path.dirname(output), naming: "server.mjs",
})
if (!result.success) throw new Error(result.logs.map(String).join("\n"))
console.log(output)
