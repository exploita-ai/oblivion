export * as OblivionTui from "./oblivion"

// Presentation surface only; VM and network isolation are enforced outside it.
const commands = new Set([
  "command.palette.show",
  "session.new",
  "session.list",
  "app.exit",
  "model.list",
  "variant.list",
  "variant.cycle",
  "help.show",
  "prompt.clear",
  "prompt.submit",
  "prompt.queue",
  "prompt.images.view",
  "prompt.stash",
  "prompt.stash.pop",
  "prompt.stash.list",
  "session.interrupt",
  "session.compact",
  "session.timeline",
  "session.rename",
  "session.delete",
  "session.undo",
  "session.redo",
  "session.first",
  "session.last",
  "session.child.first",
  "session.parent",
  "session.queued_prompts",
  "session.background",
  "session.toggle.thinking",
  "session.toggle.scrollbar",
  "session.toggle.exploration_grouping",
  "session.verbosity.cycle",
  "session.messages_last_user",
  "permission.prompt.fullscreen",
])

export function allowed(id: string) {
  return (
    commands.has(id) ||
    [
      "input.",
      "dialog.",
      "prompt.autocomplete.",
      "prompt.history.",
      "session.page.",
      "session.line.",
      "session.half.page.",
      "session.message.",
      "composer.subagent.",
      "composer.shell.",
    ].some((prefix) => id.startsWith(prefix))
  )
}

export type Action = "new" | "sessions" | "close"

export function request(action: Action) {
  // An untrusted hint only: the host asks for a fresh physical Ctrl+] before
  // closing anything. This channel carries no password or administrative IPC.
  process.stdout.write(`\x1b]777;oblivion;${action}\x07`)
}
