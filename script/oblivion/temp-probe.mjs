// Exercise production helpers with synthetic data. No provider or real editor.
import assert from "node:assert/strict"
import { access, readdir, readFile, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Effect } from "../../packages/core/node_modules/effect/dist/index.js"
import { openEditor } from "../../packages/tui/src/editor.ts"
import { BrowserFiles } from "../../packages/plugin-browser/src/files.ts"

const marker = "OBLIVION_AUDIT_SYNTHETIC_7c924e"
await access("/.dockerenv")
assert.equal(os.tmpdir(), "/out/temp-probe")
const before = new Set(await readdir(os.tmpdir()))
process.env.EDITOR = "/bin/true"
await assert.rejects(
  openEditor({
    value: marker + "_EDITOR",
    renderer: {
      suspend: () => Promise.reject(new Error("synthetic-renderer-suspend-failure")),
      resume: () => Promise.resolve(),
    },
  }),
  /synthetic-renderer-suspend-failure/,
)
const remaining = (await readdir(os.tmpdir())).filter((name) => !before.has(name))
assert.equal(remaining.length, 1)
assert.equal(await readFile(path.join(os.tmpdir(), remaining[0]), "utf8"), marker + "_EDITOR")
const captures = await Effect.runPromise(
  BrowserFiles.save([
    { id: "file_audit", name: "capture.txt", mime: "text/plain", data: new TextEncoder().encode(marker + "_BROWSER") },
  ]),
)
assert.equal(captures.length, 1)
assert.equal(await readFile(captures[0].path, "utf8"), marker + "_BROWSER")
const report = {
  editor_suspend_failure_leaves_plaintext: true,
  editor_path: path.join(os.tmpdir(), remaining[0]),
  browser_capture_persists_after_helper_returns: true,
  browser_path: captures[0].path,
}
await writeFile("/out/temp-results.json", JSON.stringify(report, null, 2) + "\n")
console.log(JSON.stringify(report))
