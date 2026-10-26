import { expect, test } from "bun:test"
import { migrateV1, resolveThemeDocument } from "../src/tui/index.js"
import type { ThemeV1Json } from "../src/tui/v1.js"

const source: ThemeV1Json = await Bun.file(
  new URL("../../tui/src/theme/assets/opencode.json", import.meta.url),
).json()
const document = migrateV1(source)

test.each(["light", "dark"] as const)("resolves %s themes without status tokens", (mode) => {
  const theme = resolveThemeDocument(document, mode)
  expect("status" in theme.text).toBeFalse()
  expect(theme.hue.accent[800]).toBeDefined()
  expect(theme.hue.interactive[800]).toBeDefined()
})

test.each(["light", "dark"] as const)("branding resolves in built-in and existing %s documents", async (mode) => {
  const { parseThemeDocument } = await import("../src/tui/index.js")
  const { opencode, oblivion } = await import("../src/tui/themes/index.js")
  const base = resolveThemeDocument(parseThemeDocument(opencode), mode)
  expect(base.text.brand).toEqual(base.hue.accent[200])
  const branded = resolveThemeDocument(parseThemeDocument(oblivion), mode)
  expect(branded.text.brand.toInts().slice(0, 3)).toEqual([211, 47, 47])
  expect(branded.surface("dialog").text.brand).toEqual(branded.text.brand)
  // Pre-existing custom documents have no brand role and use their normal text.
  const legacy = resolveThemeDocument(document, mode)
  expect(legacy.text.brand).toEqual(legacy.text.base)
  const custom = resolveThemeDocument(parseThemeDocument({ ...opencode, base: { ...opencode.base, text: { ...opencode.base.text, brand: "#123456" } } }), mode)
  expect(custom.text.brand.toInts().slice(0, 3)).toEqual([18, 52, 86])
})


test.each(["light", "dark"] as const)("action, shortcut and tool roles resolve in %s themes and custom fallbacks", async (mode) => {
  const { parseThemeDocument } = await import("../src/tui/index.js")
  const { opencode, oblivion } = await import("../src/tui/themes/index.js")
  const base = resolveThemeDocument(parseThemeDocument(opencode), mode)
  expect(base.text.shortcut).toEqual(base.text.faint)
  expect(base.text.tool).toEqual(base.text.muted)
  const branded = resolveThemeDocument(parseThemeDocument(oblivion), mode)
  expect(branded.text.shortcut).not.toEqual(branded.text.action.primary.base)
  expect(branded.text.tool).not.toEqual(branded.text.base)
  expect(branded.surface("dialog").text.tool).toEqual(branded.text.tool)
  const legacy = resolveThemeDocument(document, mode)
  expect(legacy.text.shortcut).toEqual(legacy.text.faint)
  expect(legacy.text.tool).toEqual(legacy.text.muted)
  const custom = resolveThemeDocument(parseThemeDocument({ ...opencode, base: { ...opencode.base, text: { ...opencode.base.text, shortcut: "#123456", tool: "#345678" } } }), mode)
  expect(custom.text.shortcut.toInts().slice(0, 3)).toEqual([18, 52, 86])
  expect(custom.text.tool.toInts().slice(0, 3)).toEqual([52, 86, 120])
})

test.each(["light", "dark"] as const)("debug navigation has its own role in %s themes", async (mode) => {
  const { parseThemeDocument } = await import("../src/tui/index.js")
  const { opencode, oblivion } = await import("../src/tui/themes/index.js")
  expect(resolveThemeDocument(parseThemeDocument(opencode), mode).text.debug).toEqual(resolveThemeDocument(parseThemeDocument(opencode), mode).text.base)
  expect(resolveThemeDocument(document, mode).text.debug).toEqual(resolveThemeDocument(document, mode).text.base)
  const branded = resolveThemeDocument(parseThemeDocument(oblivion), mode)
  expect(branded.text.debug).not.toEqual(branded.text.brand)
  const custom = resolveThemeDocument(parseThemeDocument({ ...opencode, base: { ...opencode.base, text: { ...opencode.base.text, debug: "#123456" } } }), mode)
  expect(custom.text.debug.toInts().slice(0, 3)).toEqual([18, 52, 86])
})
