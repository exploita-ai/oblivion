import type { CliRenderer, KeyEvent } from "@opentui/core"

const limit = 256 * 1024

// The trusted manager owns selection and explicit paste. The guest cannot read
// this socket or issue clipboard requests through its filtered terminal output.
export function createManagerClipboard(renderer: CliRenderer) {
  let text = ""
  const copy = () => {
    const selected = renderer.getSelection()?.getSelectedText() ?? ""
    if (!selected || Buffer.byteLength(selected) > limit) return ""
    text = selected
    renderer.copyToClipboardOSC52(selected)
    return selected
  }
  const paste = (value = text) => {
    if (Buffer.byteLength(value) > limit) throw new RangeError("Clipboard text is too long")
    // Plain text only. In particular a pasted escape cannot end bracketed paste.
    renderer.keyInput.processPaste(new TextEncoder().encode(value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "")))
  }
  const clear = () => { text = ""; renderer.clearSelection(); renderer.clearClipboardOSC52() }
  const keyboard = (event: KeyEvent) => {
    if (!(event.ctrl || event.super) || !["c", "v"].includes(event.name)) return
    // Without a selection Ctrl+C must still interrupt an agent/shell command.
    // Copy owns the shortcut only while there is visible selected text.
    if (event.name === "c" && !renderer.getSelection()?.getSelectedText()) return
    event.preventDefault(); event.stopPropagation()
    if (event.name === "c") { copy(); return }
    paste()
  }
  renderer.keyInput.on("keypress", keyboard)
  return { copy, paste, clear, dispose() { clear(); renderer.keyInput.off("keypress", keyboard) } }
}
