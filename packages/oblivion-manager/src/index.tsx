import { createCliRenderer } from "@opentui/core"
import { render } from "@opentui/solid"
import { theme } from "./theme"
import { createManagerClipboard } from "./clipboard"
import { SafeManager } from "./safe-manager"
import { nativeLauncher, nativePreview, readNativeStatus, type NativeRuntime } from "./native-control"

const demonstration = process.argv.includes("--preview")
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
  run: launch,
  async exit() {
    const result = await launch(process.platform === "darwin" ? ["runtime", "stop"] : ["lock"])
    if (result !== 0) throw new Error("Oblivion could not lock cleanly. Check the runtime before exiting.")
    exit()
  },
}
await render(() => <SafeManager runtime={runtime} preview={demonstration} />, renderer)
