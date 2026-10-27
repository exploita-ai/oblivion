import { expect, test } from "bun:test"
import { ControlError } from "../src/control"
import { startWhenReady } from "../src/start-chat"

test("Tor bootstrap continues automatically once the controller accepts chat startup", async () => {
  let attempts = 0
  const waiting: boolean[] = []
  await startWhenReady(async () => { if (++attempts < 3) throw new ControlError("gateway_not_ready") }, {
    signal: new AbortController().signal, wait: async () => {}, waiting: (value) => { waiting.push(value) },
  })
  expect(attempts).toBe(3)
  expect(waiting).toEqual([true, true, true, false])
})

test("cancelling bootstrap prevents another start request", async () => {
  const controller = new AbortController()
  let attempts = 0
  await expect(startWhenReady(async () => { attempts++; throw new ControlError("gateway_not_ready") }, {
    signal: controller.signal, wait: async () => { controller.abort() }, waiting: () => {},
  })).rejects.toMatchObject({ code: "chat_start_cancelled" })
  expect(attempts).toBe(1)
})

test("bootstrap retry is bounded and other startup failures are not retried", async () => {
  let attempts = 0
  await expect(startWhenReady(async () => { attempts++; throw new ControlError("gateway_not_ready") }, {
    signal: new AbortController().signal, wait: async () => {}, waiting: () => {},
  })).rejects.toMatchObject({ code: "gateway_connect_timeout" })
  expect(attempts).toBe(40)
  attempts = 0
  await expect(startWhenReady(async () => { attempts++; throw new ControlError("api_key_missing") }, {
    signal: new AbortController().signal, wait: async () => {}, waiting: () => {},
  })).rejects.toMatchObject({ code: "api_key_missing" })
  expect(attempts).toBe(1)
})


test("controller time counts toward the overall startup deadline", async () => {
  let elapsed = 0
  let attempts = 0
  await expect(startWhenReady(async () => { attempts++; elapsed += 61_000; throw new ControlError("gateway_not_ready") }, {
    signal: new AbortController().signal, now: () => elapsed, wait: async () => {}, waiting: () => {},
  })).rejects.toMatchObject({ code: "gateway_connect_timeout" })
  expect(attempts).toBe(2)
})

test("a cancellation during an accepted controller call still requires cleanup", async () => {
  const controller = new AbortController()
  const pending = Promise.withResolvers<void>()
  const accepted = Promise.withResolvers<void>()
  const result = startWhenReady(() => { accepted.resolve(); return pending.promise }, {
    signal: controller.signal, waiting: () => {},
  })
  await accepted.promise
  controller.abort()
  pending.resolve()
  await expect(result).rejects.toMatchObject({ code: "chat_start_cancelled" })
})
