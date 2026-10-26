import { useTerminalDimensions } from "@opentui/solid"
import { theme } from "./theme"

// Original cell-built wordmark. No font, image decoder or terminal graphics API.
const glyphs = [
  [" 11110 ", "11  11 ", "11  11 ", "11  11 ", "11  11 ", "11  11 ", " 11110 "],
  ["111110 ", "11  11 ", "11  11 ", "111110 ", "11  11 ", "11  11 ", "111110 "],
  ["11     ", "11     ", "11     ", "11     ", "11     ", "11     ", "111111 "],
  ["111111 ", "  11   ", "  11   ", "  11   ", "  11   ", "  11   ", "111111 "],
  ["11  11 ", "11  11 ", "11  11 ", "11  11 ", "11  11 ", " 1111  ", "  11   "],
  ["111111 ", "  11   ", "  11   ", "  11   ", "  11   ", "  11   ", "111111 "],
  [" 11110 ", "11  11 ", "11  11 ", "11  11 ", "11  11 ", "11  11 ", " 11110 "],
  ["11  11 ", "111 11 ", "111111 ", "11 111 ", "11  11 ", "11  11 ", "11  11 "],
]

export function wordmark(width: number, revealed = 8) {
  if (width < 63) return "OBLIVION".slice(0, revealed)
  const scale = width >= 119 ? 2 : 1
  return Array.from({ length: 7 }, (_, row) => glyphs.map((glyph, index) =>
    glyph[row].split("").map((cell) => (cell === "1" && index < revealed ? "█" : " ").repeat(scale)).join("")
  ).join(" ")).join("\n")
}

export function BootLogo(props: { elapsed: number }) {
  const dimensions = useTerminalDimensions()
  return <box width="100%" height="100%" backgroundColor={theme.background.boot} justifyContent="center" alignItems="center" flexDirection="column" gap={2}>
    <text fg={theme.text.brand}>{wordmark(dimensions().width - 4, Math.min(8, Math.floor(props.elapsed / 60) + 1))}</text>
    <text fg={theme.text.muted}>PRIVATE WORKSPACE</text>
  </box>
}
