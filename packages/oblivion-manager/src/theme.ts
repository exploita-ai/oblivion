import { RGBA } from "@opentui/core"
import { parseThemeDocument, resolveThemeDocument } from "@opencode/theme/tui"
import { oblivion } from "@opencode/theme/tui/themes"

export const palette = resolveThemeDocument(parseThemeDocument(oblivion), "dark")

// Compatibility names for the host shell. Both applications resolve the same
// semantic theme; these are not a second independently maintained palette.
const color = (value: RGBA, index: number) => process.env.TERM === "linux" ? RGBA.fromIndex(index) : value
export const theme = {
  background: {
    boot: RGBA.fromHex("#000000"), base: color(palette.background.base, 0), panel: color(palette.background.raised.base, 0),
    selection: color(palette.background.action.primary.focused, 8), field: color(palette.background.raised.high, 0),
  },
  text: {
    base: color(palette.text.base, 7), muted: color(palette.text.muted, 7), brand: color(palette.text.brand, 9),
    action: color(palette.text.action.primary.selected, 9), selected: color(palette.text.action.primary.focused, 0),
  },
  navigation: {
    debug: color(palette.text.debug, 11),
    active: color(palette.text.action.primary.selected, 9), inactive: color(palette.text.muted, 7), focused: color(palette.text.action.primary.focused, 0),
  },
  formfield: {
    label: color(palette.text.formfield.base, 7), focused: color(palette.text.formfield.focused, 15), marker: color(palette.text.formfield.selected, 9),
  },
  border: { base: color(palette.border.base, 8), focused: color(palette.text.formfield.focused, 9) },
  feedback: {
    warning: color(palette.text.feedback.warning.base, 11), error: color(palette.text.feedback.error.base, 9),
    success: color(palette.text.feedback.success.base, 10), info: color(palette.text.feedback.info.base, 14),
  },
}
