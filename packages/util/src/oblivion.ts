export * as Oblivion from "./oblivion.js"

// Set by the Oblivion build, never by a session's environment or config file.
declare const OBLIVION_PROFILE: boolean | undefined

export const enabled = typeof OBLIVION_PROFILE !== "undefined" && OBLIVION_PROFILE === true

const selected = typeof process === "undefined" ? undefined : process.env.OBLIVION_PROVIDER

// This only scopes the catalog and TUI. The gateway independently validates
// the selected provider, upstream origin and request privacy policy.
export const providerID = enabled && ["abliteration-ai", "refuseless", "openrouter"].includes(selected ?? "")
  ? selected!
  : "abliteration-ai"
