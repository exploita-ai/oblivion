import { BoxRenderable, ScrollBoxRenderable, TextRenderable, createCliRenderer } from "@opentui/core"

// Manual lab diagnostic. Counts pointer events only, never keys or input bytes.
const renderer = await createCliRenderer({ useMouse: true, consoleMode: "disabled", exitOnCtrlC: false, screenMode: "alternate-screen" })
const counts = { scroll: 0, down: 0, move: 0 }
const output = new TextRenderable(renderer, { height: 4, flexShrink: 0, content: "Pointer diagnostic — scroll here. No keys are recorded.", fg: "white", selectable: false })
const list = new ScrollBoxRenderable(renderer, { flexGrow: 1, minHeight: 0, scrollX: false })
const box = new BoxRenderable(renderer, { width: "100%", height: "100%", flexDirection: "column", backgroundColor: "#101014", onMouse(event) {
  if (event.type !== "scroll" && event.type !== "down" && event.type !== "move") return
  counts[event.type]++
  output.content = `Pointer diagnostic — no keys recorded.\n${JSON.stringify(counts)}\nTop ${list.scrollTop} / ${list.scrollHeight}, viewport ${list.viewport.height}\nLast wheel: ${event.scroll ? JSON.stringify(event.scroll) : "none"}`
} })
box.add(output)
Array.from({ length: 100 }, (_, index) => list.add(new TextRenderable(renderer, { content: `Diagnostic row ${index}`, height: 1, flexShrink: 0, fg: "white" })))
box.add(list)
renderer.root.add(box)
renderer.start()
