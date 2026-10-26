export * as Oblivion from "./oblivion.js"

// Set by the Oblivion build, never by a session's environment or config file.
declare const OBLIVION_PROFILE: boolean | undefined

export const enabled = typeof OBLIVION_PROFILE !== "undefined" && OBLIVION_PROFILE === true
