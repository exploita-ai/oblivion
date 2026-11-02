import { RGBA, TextAttributes } from "@opentui/core"
import { For, type JSX } from "solid-js"
import { useTerminalDimensions } from "@opentui/solid"
import { useTheme } from "../context/theme"
import { tint } from "../theme/color"
import { go, logo } from "../logo"
import { Oblivion } from "@opencode/util/oblivion"

const oblivion = [
  ["1111", "1001", "1001", "1001", "1111"],
  ["1110", "1001", "1110", "1001", "1110"],
  ["1000", "1000", "1000", "1000", "1111"],
  ["111", "010", "010", "010", "111"],
  ["10001", "10001", "10001", "01010", "00100"],
  ["111", "010", "010", "010", "111"],
  ["1111", "1001", "1001", "1001", "1111"],
  ["1001", "1101", "1011", "1001", "1001"],
]

export function Logo() {
  const theme = useTheme()
  const dimensions = useTerminalDimensions()
  if (Oblivion.enabled) {
    if (dimensions().height < 18 || dimensions().width < 52)
      return (
        <text fg={theme.text.brand} attributes={TextAttributes.BOLD} selectable={false}>
          OBLIVION
        </text>
      )

    const scale = dimensions().width >= 96 ? 2 : 1
    return (
      <box>
        <For each={[0, 1, 2, 3, 4]}>
          {(row) => (
            <text fg={theme.text.brand} attributes={TextAttributes.BOLD} selectable={false}>
              {oblivion
                .map((glyph) => glyph[row].replaceAll("1", "█".repeat(scale)).replaceAll("0", " ".repeat(scale)))
                .join(" ".repeat(scale))}
            </text>
          )}
        </For>
      </box>
    )
  }

  const renderLine = (line: string, fg: RGBA, bold: boolean): JSX.Element[] => {
    const shadow = tint(theme.background.base, fg, 0.25)
    const attrs = bold ? TextAttributes.BOLD : undefined
    return Array.from(line).map((char) => {
      if (char === "_") {
        return (
          <text fg={fg} bg={shadow} attributes={attrs} selectable={false}>
            {" "}
          </text>
        )
      }
      if (char === "^") {
        return (
          <text fg={fg} bg={shadow} attributes={attrs} selectable={false}>
            ▀
          </text>
        )
      }
      if (char === "~") {
        return (
          <text fg={shadow} attributes={attrs} selectable={false}>
            ▀
          </text>
        )
      }
      if (char === ",") {
        return (
          <text fg={shadow} attributes={attrs} selectable={false}>
            ▄
          </text>
        )
      }
      return (
        <text fg={fg} attributes={attrs} selectable={false}>
          {char}
        </text>
      )
    })
  }

  return (
    <box>
      {dimensions().height < 12 ? null : dimensions().width < 22 ? (
        <For each={go.right.slice(1)}>
          {(line) => <box flexDirection="row">{renderLine(line, theme.text.base, true)}</box>}
        </For>
      ) : dimensions().width < 44 ? (
        <>
          <For each={logo.left.slice(1)}>
            {(line) => <box flexDirection="row">{renderLine(line, theme.text.muted, false)}</box>}
          </For>
          <For each={logo.right}>
            {(line) => <box flexDirection="row">{renderLine(line, theme.text.base, true)}</box>}
          </For>
        </>
      ) : (
        <For each={logo.left}>
          {(line, index) => (
            <box flexDirection="row" gap={1}>
              <box flexDirection="row">{renderLine(line, theme.text.muted, false)}</box>
              <box flexDirection="row">{renderLine(logo.right[index()], theme.text.base, true)}</box>
            </box>
          )}
        </For>
      )}
    </box>
  )
}
