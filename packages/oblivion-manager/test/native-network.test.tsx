import { expect, test } from "bun:test"
import { testRender } from "@opentui/solid"
import { createSignal } from "solid-js"
import { nativePreview } from "../src/native-control"
import { NativeNetworkIndicator, scopedNetworkObservation, type NetworkObservation } from "../src/native-network"
import { SafeManager } from "../src/safe-manager"

test.each(["TOR READY", "SOCKS5 READY"] as const)("%s belongs to the exact host and Safe opening", async (label) => {
  const runtime = nativePreview(() => {})
  await runtime.run(["unlock"])
  const safe = (await runtime.status()).sessions[0]
  await runtime.run(["safe", "open", safe])
  const initial = await runtime.status()
  const ready = { ...initial, open_sessions: initial.open_sessions.map((entry) => ({ ...entry, mode: "agent" })), network_status: { label, direct_blocked: true, host_link: "CONNECTED" as const, age_ms: 0 } }
  const [host, setHost] = createSignal(ready)
  const [observation, setObservation] = createSignal<NetworkObservation>({ safe, state: ready, received: performance.now() })
  const app = await testRender(() => <NativeNetworkIndicator safe={safe} host={host()} observation={observation()} hostReceived={performance.now()} />, { width: 80, height: 24 })
  async function marks(tor: boolean, socks: boolean, policy = false) {
    await app.renderOnce()
    expect(app.captureCharFrame()).toContain(`Tor [${tor ? "+" : " "}]`)
    expect(app.captureCharFrame()).toContain(`SOCKS5 [${socks ? "+" : " "}]`)
    expect(app.captureCharFrame()).toContain("Network [+]")
    expect(app.captureCharFrame().includes("· Open Internet")).toBe(policy)
  }
  try {
    await marks(label === "TOR READY", label === "SOCKS5 READY", true)
    setHost({ ...ready, app_open: false, idle_lock: { ...ready.idle_lock, host: null, safes: [] }, open_sessions: [] })
    await marks(false, false)
    setHost({ ...ready, idle_lock: { ...ready.idle_lock, host: { ...ready.idle_lock.host!, nonce: "f".repeat(32) } } })
    await marks(false, false)
    setObservation({ safe, state: host(), received: performance.now() })
    await marks(label === "TOR READY", label === "SOCKS5 READY", true)
    setHost({ ...host(), idle_lock: { ...host().idle_lock, safes: host().idle_lock.safes.map((entry) => ({ ...entry, opening: { ...entry.opening, nonce: "e".repeat(32) } })) } })
    await marks(false, false)
    setObservation({ safe, state: host(), received: performance.now() })
    await marks(label === "TOR READY", label === "SOCKS5 READY", true)
    setHost({ ...host(), open_sessions: host().open_sessions.map((entry) => ({ ...entry, mode: "documents" })) })
    await marks(false, false, true)
    setHost({ ...host(), open_sessions: host().open_sessions.map((entry) => ({ ...entry, mode: "agent" })), idle_lock: { ...host().idle_lock, safes: host().idle_lock.safes.map((entry) => ({ ...entry, closing: true })) } })
    await marks(false, false)
  } finally { await app.dispose() }
})

test("Safe policy cannot come from a locked, stale or different opening observation", async () => {
  const runtime = nativePreview(() => {})
  await runtime.run(["unlock"])
  const safe = (await runtime.status()).sessions[0]
  await runtime.run(["safe", "open", safe])
  const state = { ...await runtime.status(), safe_access: { current: "strict" as const, saved: "strict" as const, temporary: false }, network_status: { label: "OFFLINE · NO NETWORK DEVICE" as const, direct_blocked: true, host_link: "CONNECTED" as const, age_ms: 0 } }
  const now = performance.now()
  const observation = { safe, state, received: now }
  expect(scopedNetworkObservation(observation, safe, state, now)?.safe_access.current).toBe("strict")
  expect(scopedNetworkObservation(observation, safe, state, now + 10_001)).toBeUndefined()
  expect(scopedNetworkObservation(observation, state.sessions[1], state, now)).toBeUndefined()
  expect(scopedNetworkObservation(observation, safe, { ...state, app_open: false }, now)).toBeUndefined()
  expect(scopedNetworkObservation({ ...observation, state: { ...state, app_open: false } }, safe, state, now)).toBeUndefined()
  expect(scopedNetworkObservation(observation, safe, { ...state, idle_lock: { ...state.idle_lock, safes: state.idle_lock.safes.map((entry) => ({ ...entry, opening: { ...entry.opening, nonce: "e".repeat(32) } })) } }, now)).toBeUndefined()
})

test.each([[80, 24], [160, 50]])("footer uses only the selected Safe's scoped policy at %ix%i", async (width, height) => {
  const fixture = nativePreview(() => {})
  await fixture.run(["unlock"])
  const safe = (await fixture.status()).sessions[0]
  await fixture.run(["safe", "open", safe])
  const initial = await fixture.status()
  const state = { ...initial, open_sessions: initial.open_sessions.map((entry) => ({ ...entry, mode: "agent" })), network_status: { label: "TOR READY" as const, direct_blocked: true, host_link: "CONNECTED" as const, age_ms: 0 } }
  const [policy, setPolicy] = createSignal<"open" | "strict" | "offline">("strict")
  const runtime = { ...fixture, status: async () => state, query: async (args: string[]) => args[0] === "network" ? { ...state, safe_access: { ...state.safe_access, current: policy() }, network_status: { ...state.network_status, label: policy() === "offline" ? "OFFLINE" : "TOR READY" } } : fixture.query(args) }
  const app = await testRender(() => <SafeManager runtime={runtime} />, { width, height, kittyKeyboard: true })
  async function visible(value: string) {
    const deadline = performance.now() + 2000
    while (performance.now() < deadline) {
      await app.renderOnce()
      if (app.captureCharFrame().includes(value)) return
      await Bun.sleep(5)
    }
    throw new Error(`Missing ${value}\n${app.captureCharFrame()}`)
  }
  try {
    await visible("Network [+] · Strict")
    expect(app.captureCharFrame()).not.toContain("· Open Internet")
    expect(app.captureCharFrame()).toContain("Tor [+]")
    expect(app.captureCharFrame()).toContain("SOCKS5 [ ]")
    expect(app.captureCharFrame()).toContain("Lock Oblivion")
    setPolicy("open")
    await app.mockInput.pressKey("r")
    await visible("Network [+] · Open Internet")
    expect(app.captureCharFrame()).toContain("Lock Oblivion")
    setPolicy("offline")
    await app.mockInput.pressKey("r")
    await visible("Network [+] · Offline")
    expect(app.captureCharFrame()).toContain("Tor [ ]")
    expect(app.captureCharFrame()).toContain("Lock Oblivion")
  } finally { await app.dispose() }
})
