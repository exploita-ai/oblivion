import { createCliRenderer } from "@opentui/core"
import { render } from "@opentui/solid"
import { theme } from "./theme"
import { createManagerClipboard } from "./clipboard"
import { SafeManager } from "./safe-manager"
import { createNativeFileClient } from "./native-file-process"
import { createNativeFilePicker } from "./native-file-picker"
import { createNativeUsbClient } from "./native-usb"
import { launchNativeAgent, type AgentEvent } from "./native-agent"
import { Startup } from "./startup"
import { chooseLiveStorage, nativeLauncher, nativeOverlay, nativePreview, readNativeJson, readNativeStatus, reportNativeActivity, statusReader, type NativeRuntime } from "./native-control"

const demonstration = process.argv.includes("--preview")
const overlay = nativeOverlay(process.argv.slice(2))
const liveStorage = demonstration ? undefined : process.env.OBLIVION_LIVE_STORAGE
if (liveStorage !== undefined && liveStorage !== "persistent" && liveStorage !== "ephemeral") throw new Error("Invalid Live storage mode")
const intro = !demonstration && !overlay && liveStorage !== undefined && process.env.OBLIVION_SHOW_INTRO === "1"
delete process.env.OBLIVION_SHOW_INTRO
// A cold Linux virtual console may still interpret output as an 8-bit charset.
// Select UTF-8 before OpenTUI draws its borders or accepts non-ASCII input.
if (process.env.TERM === "linux") process.stdout.write("\u001b%G")
const renderer = await createCliRenderer({
  exitOnCtrlC: false, consoleMode: "disabled", openConsoleOnError: false,
  screenMode: "alternate-screen", backgroundColor: theme.background.base,
  useMouse: true, targetFps: 60, gatherStats: false,
})
const clipboard = createManagerClipboard(renderer)
const exit = () => { clipboard.dispose(); renderer.destroy(); process.exit(0) }

function runsWithoutTerminal(args: string[]) {
  return (args[0] === "settings" && args[1] === "idle")
    || (args[0] === "safe" && args[1] === "open" && args[3] === "--already-open")
    || (args[0] === "files" && (args[1] === "recover" || args[1] === "discard") && args.at(-1) === "--json")
    || (args[0] === "network" && args[1] === "set" && args[2] === "--safe"
      && (args[4] === "--policy" || args[4] === "--tor"))
}

async function launch(args: string[], reportAgentEvent?: (event: AgentEvent) => void) {
  if (runsWithoutTerminal(args)) {
    return Bun.spawn([nativeLauncher(), ...args], { stdin: "ignore", stdout: "ignore", stderr: "ignore" }).exited
  }
  if (args[0] === "run" && reportAgentEvent && process.platform !== "win32") {
    return launchNativeAgent(nativeLauncher(), args, renderer, reportAgentEvent)
  }
  await renderer.suspend()
  try {
    const child = Bun.spawn([nativeLauncher(), ...args], {
      stdin: "inherit", stdout: "inherit", stderr: "inherit",
    })
    return await child.exited
  } finally {
    await renderer.resume()
  }
}

const fileClient = { current: createNativeFileClient(nativeLauncher()) }
const usb = liveStorage ? createNativeUsbClient(nativeLauncher()) : undefined
const picker = !demonstration && !liveStorage && (process.platform !== "linux" || process.env.WAYLAND_DISPLAY || process.env.DISPLAY)
  ? createNativeFilePicker(nativeLauncher()) : undefined
const runtime: NativeRuntime = demonstration ? nativePreview(exit) : {
  get files() { return fileClient.current },
  usb,
  pickFiles: picker?.choose,
  status: statusReader((initial) => readNativeStatus(nativeLauncher(), initial && !overlay ? 400_000 : 10_000)),
  query: (args) => readNativeJson(nativeLauncher(), args),
  activity: (input) => reportNativeActivity(nativeLauncher(), input),
  run: launch,
  ...(liveStorage && !overlay ? { chooseLiveStorage: () => chooseLiveStorage(fileClient.current, launch, exit,
    () => { fileClient.current = createNativeFileClient(nativeLauncher()) }) } : {}),
  async exit() {
    await picker?.close()
    const usbClosed = await usb?.close().then(() => true, () => false) ?? true
    await fileClient.current.close()
    if (overlay) {
      if (!usbClosed) throw new Error("USB removal was not confirmed. Check the runtime before continuing.")
      exit(); return
    }
    const result = await launch(process.env.OBLIVION_RUNTIME_MODE === "desktop" ? ["runtime", "stop"] : ["lock"])
    if (result !== 0) throw new Error("Oblivion could not lock cleanly. Check the runtime before exiting.")
    if (!usbClosed) throw new Error("Oblivion is locked. USB removal could not be confirmed.")
    exit()
  },
}
const initial = intro ? runtime.status().then((state) => ({ state, received: performance.now() })) : undefined
await render(() => intro ? <Startup runtime={runtime} initial={initial!} liveStorage={liveStorage} /> : <SafeManager runtime={runtime} preview={demonstration} overlay={overlay} liveStorage={liveStorage} />, renderer)
