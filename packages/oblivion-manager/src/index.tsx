import { createCliRenderer } from "@opentui/core"
import { render } from "@opentui/solid"
import { theme } from "./theme"
import { createManagerClipboard } from "./clipboard"
import { SafeManager } from "./safe-manager"
import { Startup } from "./startup"
import { nativeLauncher, nativeOverlay, nativePreview, readNativeJson, readNativeStatus, reportNativeActivity, type NativeRuntime } from "./native-control"

const demonstration = process.argv.includes("--preview")
const overlay = nativeOverlay(process.argv.slice(2))
const liveStorage = demonstration ? undefined : process.env.OBLIVION_LIVE_STORAGE
if (liveStorage !== undefined && liveStorage !== "persistent" && liveStorage !== "ephemeral") throw new Error("Invalid Live storage mode")
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

async function launch(args: string[]) {
  await renderer.suspend()
  try {
    const child = Bun.spawn([nativeLauncher(), ...args], {
      stdin: "inherit", stdout: "inherit", stderr: "inherit",
      env: { ...process.env, OBLIVION_MANAGER_ACTIVE: "1" },
    })
    return await child.exited
  } finally {
    await renderer.resume()
  }
}

const runtime: NativeRuntime = demonstration ? nativePreview(exit) : {
  status: () => readNativeStatus(nativeLauncher()),
  query: (args) => readNativeJson(nativeLauncher(), args),
  activity: (input) => reportNativeActivity(nativeLauncher(), input),
  run: launch,
  async exit() {
    if (overlay) { exit(); return }
    const result = await launch(process.env.OBLIVION_RUNTIME_MODE === "desktop" ? ["runtime", "stop"] : ["lock"])
    if (result !== 0) throw new Error("Oblivion could not lock cleanly. Check the runtime before exiting.")
    exit()
  },
}
const intro = !demonstration && !overlay && liveStorage !== undefined && process.env.OBLIVION_SHOW_INTRO === "1"
const initial = intro ? runtime.status().then((state) => ({ state, received: performance.now() }), () => undefined) : undefined
await render(() => intro ? <Startup runtime={runtime} initial={initial!} liveStorage={liveStorage} /> : <SafeManager runtime={runtime} preview={demonstration} overlay={overlay} liveStorage={liveStorage} />, renderer)
