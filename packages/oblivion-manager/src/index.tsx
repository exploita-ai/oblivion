import { createCliRenderer } from "@opentui/core"
import { render } from "@opentui/solid"
import { App, type Runtime } from "./app"
import { ControlError, request } from "./control"
import { preview } from "./preview"
import { theme } from "./theme"
import { connectChat, connectTerminal } from "./chat"
import { createManagerClipboard } from "./clipboard"

const demonstration = process.argv.includes("--preview")
if (!demonstration && (process.platform !== "linux" || process.getuid?.() !== 1000)) {
  process.stderr.write("Run the trusted manager as the Oblivion user on Linux, or use --preview.\n")
  process.exit(1)
}
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

async function helper(mode: string) {
  await renderer.suspend()
  try {
    const child = Bun.spawn(["/usr/bin/oblivion-console", mode], {
      stdin: "inherit", stdout: "inherit", stderr: "ignore",
      env: { PATH: "/usr/bin:/bin", HOME: "/run/oblivion-manager", TERM: process.env.TERM ?? "linux" },
    })
    const result = await child.exited
    if (result !== 0 && result !== 10) throw new ControlError("console_failed")
    return result
  } finally {
    await renderer.resume()
  }
}

const runtime: Runtime = demonstration ? preview(exit) : {
  request,
  connectChat,
  connectTerminal,
  clearClipboard: clipboard.clear,
  async console() { return await helper("--console") === 10 ? "new" : "sessions" },
  async documents() { await helper("--documents") },
  exit,
}
await render(() => <App runtime={runtime} preview={demonstration} documentsOnly={process.argv.includes("--documents")} />, renderer)
