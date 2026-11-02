import { describe, expect, test } from "bun:test"
import { idleLockAction } from "../src/idle-lock"

describe("idle lock policy", () => {
  test("locks an open session at its inactivity threshold", () => {
    expect(idleLockAction({
      elapsedMs: 15 * 60_000,
      generalMounted: true,
      sessionOpen: true,
      sessionMinutes: 15,
      hostMinutes: 30,
    })).toBe("session")
  })

  test("locks Oblivion at the host threshold even when a session is open", () => {
    expect(idleLockAction({
      elapsedMs: 30 * 60_000,
      generalMounted: true,
      sessionOpen: true,
      sessionMinutes: 15,
      hostMinutes: 30,
    })).toBe("host")
  })

  test("does nothing while locked or before a configured threshold", () => {
    expect(idleLockAction({ elapsedMs: 60_000, generalMounted: false, sessionOpen: true, sessionMinutes: 0, hostMinutes: 0 })).toBeUndefined()
    expect(idleLockAction({ elapsedMs: 14 * 60_000, generalMounted: true, sessionOpen: true, sessionMinutes: 15, hostMinutes: 30 })).toBeUndefined()
  })

  test("supports disabling either timeout independently", () => {
    expect(idleLockAction({ elapsedMs: 20 * 60_000, generalMounted: true, sessionOpen: true, sessionMinutes: 0, hostMinutes: 30 })).toBeUndefined()
    expect(idleLockAction({ elapsedMs: 20 * 60_000, generalMounted: true, sessionOpen: true, sessionMinutes: 15, hostMinutes: 0 })).toBe("session")
  })
})
