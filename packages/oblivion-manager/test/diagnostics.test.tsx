import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { Diagnostics } from "../src/diagnostics"

test.each([[80, 24], [160, 50]])("diagnostics are reviewed before export at %ix%i", async (width, height) => {
  const actions: string[] = []
  const saved: string[] = []
  const path = `workspace/diagnostics/${"b".repeat(32)}.json`
  const app = await testRender(() => <Diagnostics back={() => {}} saved={async (path) => { saved.push(path) }} request={async (request) => {
    expect(request.operation).toBe("diagnostics")
    const value = JSON.parse(new TextDecoder().decode(request.payload)) as { action: string }
    actions.push(value.action)
    return JSON.stringify(value.action === "export" ? { result: "exported", path, bytes: 512 } : {
      version: 1, controller_version: "0.1.0", architecture: "aarch64", cpu_cores: 4, memory_mib: 4096,
      ephemeral: false, general_open: true, session: "documents", transport: "offline", direct_access_blocked: true,
      observation_age_ms: 0, tor_bootstrap: null, laboratory: false,
    })
  }} />, { width, height, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Export diagnostics / Review")
    expect(app.captureCharFrame()).toContain("controller_version: 0.1.0")
    expect(app.captureCharFrame()).toContain("Create JSON report in session")
    expect(actions).toEqual(["preview"])
    await app.mockInput.pressEnter(); await app.renderOnce()
    expect(actions).toEqual(["preview", "export"])
    expect(saved).toEqual([path])
  } finally { await app.dispose() }
})

test("an invalid diagnostic response never exposes its content and still allows Back", async () => {
  let returned = false
  const app = await testRender(() => <Diagnostics back={() => { returned = true }} saved={async () => { throw new Error("must not export") }} request={async () => JSON.stringify({
    api_key: "PRIVATE_RESPONSE_MUST_NOT_BE_SHOWN", logs: "/private/path", version: 999,
  })} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Diagnostics could not be created")
    expect(app.captureCharFrame()).not.toContain("PRIVATE_RESPONSE")
    expect(app.captureCharFrame()).not.toContain("/private/path")
    expect(app.captureCharFrame()).not.toContain("Create JSON report")
    await app.mockInput.pressEnter()
    expect(returned).toBe(true)
  } finally { await app.dispose() }
})
