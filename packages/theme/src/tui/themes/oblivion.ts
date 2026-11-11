import base from "./base.json" with { type: "json" }

// Derived from OpenCode's MIT-licensed semantic defaults; see the root LICENSE.
// Oblivion defines its own brand, interaction palette and neutral surfaces.
const brand = {
  100: "#ffcdd2", 200: "#d32f2f", 300: "#c62828", 400: "#b71c1c", 500: "#9c2020",
  600: "#7c1b1b", 700: "#5d1717", 800: "#3d1212", 900: "#210c0c",
}
export const oblivion = {
  ...base,
  base: { ...base.base, text: { ...base.base.text, brand: "$hue.brand.200", debug: "$hue.orange.200", shortcut: "$hue.orange.200", tool: "$hue.cyan.200" }, categorical: ["brand", "orange", "green", "cyan"] },
  light: {
    ...base.light,
    categorical: ["brand", "orange", "green", "cyan"],
    hue: { ...base.light.hue, brand, accent: "$hue.brand", interactive: "$hue.brand" },
    text: { ...base.light.text, action: { primary: { base: "$hue.cyan.200" }, secondary: { base: "$hue.blue.200" } }, feedback: { ...base.light.text.feedback, warning: { base: "$hue.orange.200" } } },
  },
  dark: {
    ...base.dark,
    text: { debug: "#e5c07b", shortcut: "#e5c07b", tool: "#70cbd6", action: { primary: { base: "#70cbd6", $focused: "#ffffff" }, secondary: { base: "#9bbcf2", $focused: "#ffffff" } } },
    background: { action: { primary: { $focused: "#30303c" } } },
    categorical: ["brand", "orange", "green", "cyan"],
    hue: {
      ...base.dark.hue,
      brand,
      accent: "$hue.brand",
      interactive: { ...brand, 200: "#ef9a9a" },
      gray: {
        100: "#ffffff", 200: "#e4e4ec", 300: "#b6b6c4", 400: "#92929f", 500: "#34343f",
        600: "#22222c", 700: "#17171d", 800: "#101014", 900: "#0b0b0f",
      },
    },
    border: { base: "#34343f" },
  },
}
