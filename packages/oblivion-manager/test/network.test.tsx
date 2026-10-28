import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { App } from "../src/app"
import { ControlError } from "../src/control"
import { preview } from "../src/preview"
import { status } from "../src/state"

test.each([
  ["local", "Network [+]"],
  ["available", "Network [+]"],
  ["offline", "Network [ ]"],
  ["unknown", "Network [?]"],
] as const)("welcome reports the %s connection independently of privacy routes", async (internet, expected) => {
  const runtime = preview(() => {})
  await runtime.request({ operation: "lock" })
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  initial.connections!.internet = internet
  const app = await testRender(() => <App runtime={runtime} initial={initial} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    for (const [width, height] of [[80, 24], [160, 50]]) {
      app.resize(width, height); await app.renderOnce()
      const footer = app.captureCharFrame().split("\n").slice(-4).join("\n")
      expect(footer).toContain(`${expected}   Tor [ ]   SOCKS5 [ ]`)
      expect(footer).not.toContain("Internet")
    }
  } finally { await app.dispose() }
})

for (const ephemeral of [false, true]) {
  test.each([[80, 24], [160, 50]])(`Network stays in the ${ephemeral ? "ephemeral" : "persistent"} manager at %ix%i`, async (width, height) => {
    const runtime = preview(() => {})
    if (ephemeral) await runtime.request({ operation: "unlock-ephemeral" })
    const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
    const app = await testRender(() => <App runtime={runtime} initial={initial} />, { width, height, kittyKeyboard: true })
    try {
      await app.renderOnce(); await app.mockInput.pressKey("2"); await app.renderOnce()
      expect(app.captureCharFrame()).toContain("HOST / Network / Connection")
      expect(app.captureCharFrame()).toContain("Ethernet · eth0")
      expect(app.captureCharFrame()).toContain("Network [+]   Tor [ ]   SOCKS5 [ ]")
      expect(app.captureCharFrame()).toContain("API keys")
      await app.mockInput.pressArrow("right"); await app.renderOnce()
      expect(app.captureCharFrame()).toContain("HOST / Network / Privacy")
      expect(app.captureCharFrame()).toContain("SOCKS5 proxy")
      await app.mockInput.pressEnter(); await app.mockInput.pressEnter(); await app.renderOnce()
      expect(app.captureCharFrame()).toContain("Use Tor")
      expect(app.captureCharFrame()).not.toContain("Save encrypted")
      await app.mockInput.pressEscape(); await app.renderOnce()
      await app.mockInput.pressArrow("right"); await app.renderOnce()
      expect(app.captureCharFrame()).toContain("HOST / Network / Rules")
      expect(app.captureCharFrame()).toContain("Add rule")
      await app.mockInput.pressKey("n"); await app.renderOnce()
      await app.mockInput.typeText("example.org")
      for (let i = 0; i < 4; i++) await app.mockInput.pressEnter()
      await app.renderOnce()
      expect(app.captureCharFrame()).toContain("DENY example.org:443")
      expect(app.captureCharFrame()).toContain("HOST / Network / Rules")
      const updated = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
      expect(updated.network_policy?.temporary).toBe(ephemeral)
      expect(updated.network_policy?.policy.rules).toEqual([{ destination: "example.org", port: 443, action: "deny" }])
      const rows = app.captureCharFrame().split("\n")
      const tab = rows.findIndex((row) => row.includes("Connection") && row.includes("Privacy") && row.includes("Rules"))
      await app.mockMouse.click(rows[tab].indexOf("Connection") + 2, tab); await app.renderOnce()
      expect(app.captureCharFrame()).toContain("HOST / Network / Connection")
      await app.mockInput.pressKey("TAB", { shift: true }); await app.mockInput.pressArrow("up"); await app.mockInput.pressEnter(); await app.renderOnce()
      expect(app.captureCharFrame()).toContain("HOST / Sessions")
    } finally { await app.dispose() }
  })
}

test("Wi-Fi failure stays in Network and never displays the secret", async () => {
  const fixture = preview(() => {})
  await fixture.request({ operation: "unlock-ephemeral" })
  const initial = status.parse(JSON.parse(await fixture.request({ operation: "status" })))
  const requests: string[] = []
  const app = await testRender(() => <App initial={initial} runtime={{ ...fixture, request: async (input) => {
    requests.push(input.operation)
    if (input.operation === "connections") {
      expect(JSON.parse(new TextDecoder().decode(input.payload))).toEqual({ action: "connect", device: "wlan0", bssid: "02:00:00:00:00:01", password: "synthetic-wifi-password" })
      throw new ControlError("network_connection_failed")
    }
    return fixture.request(input)
  } }} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("2"); await app.mockInput.pressEnter()
    await app.mockInput.pressArrow("down"); await app.mockInput.pressArrow("down"); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Connect to Home Wi-Fi")
    await app.mockInput.typeText("synthetic-wifi-password"); await app.renderOnce()
    expect(app.captureCharFrame()).not.toContain("synthetic-wifi-password")
    expect(app.captureCharFrame()).not.toContain("Save encrypted")
    await app.mockInput.pressEnter(); await app.mockInput.pressEnter(); await app.mockInput.pressEnter(); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("Could not connect")
    expect(app.captureCharFrame()).toContain("HOST / Network / Connection")
    expect(app.captureCharFrame()).toContain("Network [+]")
    expect(requests).toContain("connections")
    expect(requests).not.toContain("save-network")
    expect(requests).not.toContain("network-menu")
  } finally { await app.dispose() }
})

test.each([null, { internet: "local" as const, wifi_enabled: false, devices: [{ name: "eth0", kind: "ethernet" as const, state: "connected" }], access_points: [] }])("missing network data or Wi-Fi hardware remains navigable", async (connections) => {
  const runtime = preview(() => {})
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  initial.connections = connections ? { ...connections, devices: [...connections.devices], access_points: [] } : null
  const app = await testRender(() => <App runtime={runtime} initial={initial} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("2"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain(connections ? "No Wi-Fi adapter detected" : "NetworkManager is unavailable")
    expect(app.captureCharFrame()).toContain(connections ? "Network [+]" : "Network [?]")
    expect(app.captureCharFrame()).not.toContain("Refresh Wi-Fi networks")
    await app.mockInput.pressArrow("right"); await app.renderOnce()
    expect(app.captureCharFrame()).toContain("HOST / Network / Privacy")
  } finally { await app.dispose() }
})

test("large Wi-Fi lists scroll without hiding tabs or footer", async () => {
  const runtime = preview(() => {})
  const initial = status.parse(JSON.parse(await runtime.request({ operation: "status" })))
  initial.connections!.access_points = Array.from({ length: 100 }, (_, index) => ({ device: "wlan0", bssid: `02:00:00:00:00:${index.toString(16).padStart(2, "0")}`, ssid: `Wi-Fi ${index.toString().padStart(3, "0")}`, security: "WPA2", signal: 70, active: false }))
  const app = await testRender(() => <App runtime={runtime} initial={initial} />, { width: 80, height: 24, kittyKeyboard: true })
  try {
    await app.renderOnce(); await app.mockInput.pressKey("2"); await app.mockInput.pressEnter()
    for (let i = 0; i < 101; i++) await app.mockInput.pressArrow("down")
    for (const [width, height] of [[80, 24], [160, 50]]) {
      app.resize(width, height); await app.renderOnce()
      const frame = app.captureCharFrame()
      expect(frame).toContain("Wi-Fi 099")
      expect(frame).not.toContain("Wi-Fi 000")
      expect(frame).toMatch(/Connection\s+Privacy\s+Rules/)
      expect(frame).toContain("Network [+]   Tor [ ]   SOCKS5 [ ]")
      expect(frame.split("\n")).toHaveLength(height + 1)
    }
  } finally { await app.dispose() }
})
