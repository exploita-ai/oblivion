import { expect, test } from "bun:test"
import { rotationResult, unconfirmed } from "../src/rotation"

test("accepts only successful, validated rotation replies", () => {
  expect(rotationResult(200, '{"status":"rotated"}')).toEqual({ status: "rotated" })
  expect(rotationResult(200, '{"status":"renewed"}')).toEqual({ status: "renewed" })
  for (const [status, body] of [
    [503, '{"status":"rotated"}'],
    [200, '{"status":"unknown"}'],
    [200, '{"status":"rotated","token":"private"}'],
    [200, '{"status":"rotated","phase":"unexpected"}'],
    [200, 'upstream error: Bearer private'],
  ] as const) expect(rotationResult(status, body)).toEqual({ error: unconfirmed })
})

test("returns closed failure messages without exposing gateway response details", () => {
  expect(rotationResult(503, '{"status":"blocked","phase":"isolation"}')).toMatchObject({
    error: expect.stringContaining("traffic remains blocked"),
  })
  expect(rotationResult(429, '{"status":"cooldown"}')).toMatchObject({
    error: expect.stringContaining("Do not retry in a loop"),
  })
  expect(rotationResult(409, '{"status":"tor_required"}')).toMatchObject({
    error: expect.stringContaining("SOCKS5 and Offline"),
  })
  expect(rotationResult(401, '{"status":"unauthorized"}')).toMatchObject({
    error: expect.stringContaining("Provider API keys cannot authorize"),
  })
})
