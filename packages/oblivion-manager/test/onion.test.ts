import { expect, test } from "bun:test"
import { base32, createOnionRecipient, onionStatusSchema, onionVerified } from "../src/onion"

test("raw key encoding uses canonical unpadded RFC 4648 base32", () => {
  for (const [plain, encoded] of [["", ""], ["f", "MY"], ["fo", "MZXQ"], ["foo", "MZXW6"], ["foob", "MZXW6YQ"], ["fooba", "MZXW6YTB"], ["foobar", "MZXW6YTBOI"]]) {
    expect(base32(new TextEncoder().encode(plain))).toBe(encoded)
  }
})

test("real X25519 recipient keys are fresh, private by default and disposed explicitly", () => {
  const first = createOnionRecipient()
  const second = createOnionRecipient()
  try {
    expect(first.publicKey).toMatch(/^[A-Z2-7]{51}[AQ]$/)
    expect(first.publicKey).not.toBe(second.publicKey)
    const secret = first.reveal()
    expect(secret).toMatch(/^[A-Z2-7]{51}[AQ]$/)
    expect(secret).not.toBe(first.publicKey)
    expect(JSON.stringify(first)).toBe(JSON.stringify({ publicKey: first.publicKey }))
    expect(JSON.stringify(first)).not.toContain(secret)
    first.dispose()
    expect(() => first.reveal()).toThrow("onion_closed")
  } finally { first.dispose(); second.dispose() }
})

test("a stale or incomplete transfer observation cannot authorize publication", () => {
  const value = { configured: true, active: true, id: "a".repeat(32), phase: "ready", tor_progress: 100, tor_ready: true, age_ms: 0, progress: null, receipt: null }
  expect(onionStatusSchema.parse(value).tor_ready).toBe(true)
  expect(onionStatusSchema.parse({ ...value, tor_progress: 99 }).tor_ready).toBe(false)
  expect(onionStatusSchema.parse({ ...value, age_ms: 10_001 })).toMatchObject({ tor_ready: false, tor_progress: null })
  expect(onionStatusSchema.safeParse({ ...value, tor_progress: 101 }).success).toBe(false)
  expect(onionStatusSchema.safeParse({ ...value, private_key: "unexpected" }).success).toBe(false)
  expect(onionVerified(value, 10_000)).toBe(true)
  expect(onionVerified(value, 10_001)).toBe(false)
  expect(onionVerified({ ...value, age_ms: 4000 }, 6001)).toBe(false)
})
