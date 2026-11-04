import { expect, test } from "bun:test"
import { parseThemeDocument, resolveThemeDocument } from "../src/tui/index.js"
import { base, oblivion } from "../src/tui/themes/index.js"

test.each(["light", "dark"] as const)("resolves complete semantic defaults in %s mode", (mode) => {
  const theme = resolveThemeDocument(parseThemeDocument(base), mode)
  expect("status" in theme.text).toBeFalse()
  expect(theme.hue.accent[800]).toBeDefined()
  expect(theme.hue.interactive[800]).toBeDefined()
  expect(theme.text.brand).toEqual(theme.hue.accent[200])
  expect(theme.text.shortcut).toEqual(theme.text.faint)
  expect(theme.text.tool).toEqual(theme.text.muted)
})

test.each(["light", "dark"] as const)("Oblivion branding and contextual roles resolve in %s mode", (mode) => {
  const theme = resolveThemeDocument(parseThemeDocument(oblivion), mode)
  expect(theme.text.brand.toInts().slice(0, 3)).toEqual([211, 47, 47])
  expect(theme.surface("dialog").text.brand).toEqual(theme.text.brand)
  expect(theme.text.shortcut).not.toEqual(theme.text.action.primary.base)
  expect(theme.text.tool).not.toEqual(theme.text.base)
  expect(theme.surface("dialog").text.tool).toEqual(theme.text.tool)
  expect(theme.text.debug).not.toEqual(theme.text.brand)
})

test.each(["light", "dark"] as const)("optional semantic roles use defaults or custom values in %s mode", (mode) => {
  const text = Object.fromEntries(Object.entries(base.base.text).filter(([key]) => !["brand", "debug", "shortcut", "tool"].includes(key)))
  const fallback = resolveThemeDocument(parseThemeDocument({ ...base, base: { ...base.base, text } }), mode)
  expect(fallback.text.brand).toEqual(fallback.text.base)
  expect(fallback.text.debug).toEqual(fallback.text.base)
  expect(fallback.text.shortcut).toEqual(fallback.text.faint)
  expect(fallback.text.tool).toEqual(fallback.text.muted)
  const custom = resolveThemeDocument(parseThemeDocument({ ...base, base: { ...base.base, text: { ...text, brand: "#123456", debug: "#234567", shortcut: "#345678", tool: "#456789" } } }), mode)
  expect(custom.text.brand.toInts().slice(0, 3)).toEqual([18, 52, 86])
  expect(custom.text.debug.toInts().slice(0, 3)).toEqual([35, 69, 103])
  expect(custom.text.shortcut.toInts().slice(0, 3)).toEqual([52, 86, 120])
  expect(custom.text.tool.toInts().slice(0, 3)).toEqual([69, 103, 137])
})
