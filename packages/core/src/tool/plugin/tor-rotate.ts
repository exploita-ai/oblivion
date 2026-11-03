export * as TorRotateTool from "./tor-rotate.js"

import type { Context } from "@opencode/plugin/effect/plugin"
import { ToolFailure } from "@opencode/ai"
import { Effect, Schema } from "effect"
import { HttpClient, HttpClientRequest } from "effect/http"
import { Permission } from "../../permission.js"

export const name = "tor_rotate"
export const Input = Schema.Struct({})
export const Output = Schema.Struct({ status: Schema.Literals(["rotated", "renewed"]) })
const Reply = Schema.Struct({
  status: Schema.Literals([
    "rotated",
    "renewed",
    "blocked",
    "tor_required",
    "cooldown",
    "rotation_in_progress",
    "controller_unavailable",
    "unauthorized",
    "rotation_not_allowed",
  ]),
})

export const Plugin = {
  id: "oblivion.tool.tor-rotate",
  effect: Effect.fn("TorRotateTool.Plugin")(function* (ctx: Context) {
    const http = yield* HttpClient.HttpClient
    const permission = yield* Permission.Service
    yield* ctx.tool
      .transform((editor) =>
        editor.add({
          name,
          options: { codemode: false },
          description:
            "Rotate Tor exit circuits for this protected Oblivion session. Interrupts ALL ongoing model requests, downloads and connections in its chats and terminals. The controller blocks application traffic first and leaves it blocked on rotation failure. Use when the user requests rotation or a site rejects a Tor exit; never loop or use it to retry a rate limit. Requires Tor, not SOCKS5. No arguments; no direct fallback. A new exit relay does not guarantee the site will accept access.",
          input: Input,
          output: Output,
          execute: (_input, context) =>
            Effect.gen(function* () {
              yield* permission.assert({
                action: name,
                resources: ["current-protected-session"],
                save: ["current-protected-session"],
                metadata: {},
                sessionID: context.sessionID,
                agent: context.agent,
                source: { type: "tool", messageID: context.messageID, id: context.id },
              })
              const token = process.env.OBLIVION_API_TOKEN
              if (!token || !/^[a-f0-9]{64}$/.test(token)) {
                return yield* Effect.fail(new ToolFailure({ message: "Tor rotation capability unavailable." }))
              }
              const response = yield* http.execute(
                HttpClientRequest.post("http://10.88.0.1:8114/tor/rotate").pipe(
                  HttpClientRequest.setHeader("Authorization", `Bearer ${token}`),
                ),
              )
              const result = yield* response.json.pipe(Effect.flatMap(Schema.decodeUnknownEffect(Reply)))
              if (result.status !== "rotated" && result.status !== "renewed") {
                const messages = {
                  blocked:
                    "Tor rotation failed. This protected session's external traffic remains blocked. The user can retry rotation or close and reopen the protected session.",
                  tor_required: "Tor rotation is unavailable in SOCKS5 or Offline mode. No network policy was changed.",
                  cooldown:
                    "Tor rotation is rate limited. Wait at least 30 seconds between attempts; do not retry in a loop.",
                  rotation_in_progress:
                    "A rotation is already in progress for this protected session. Do not submit another.",
                  controller_unavailable:
                    "Tor rotation controller is unavailable. Success is unconfirmed; check the manager's network status.",
                  rotation_not_allowed:
                    "Tor rotation is not enabled for this opening. Close any OnionShare transfer first. Older host builds require an update; no rotation was started.",
                  unauthorized: "Tor rotation capability was rejected. Do not substitute a provider API key.",
                }
                return yield* Effect.fail(new ToolFailure({ message: messages[result.status] }))
              }
              if (response.status !== 200)
                return yield* Effect.fail(
                  new ToolFailure({ message: "Tor rotation returned an inconsistent result. Success is unconfirmed." }),
                )
              return {
                output: { status: result.status },
                content:
                  result.status === "rotated"
                    ? "Tor circuits rebuilt and previous exit relays excluded. Isolation verified; session traffic reopened. Previous connections were closed."
                    : "Fresh Tor circuits verified; session traffic reopened. No previous exit relay was available for comparison.",
                metadata: {},
              }
            }).pipe(
              Effect.timeout("160 seconds"),
              // Never attach HTTP errors: their request headers contain a capability.
              Effect.mapError((error) =>
                error instanceof ToolFailure
                  ? error
                  : new ToolFailure({
                      message:
                        "Tor rotation could not be confirmed. Do not assume connectivity or retry automatically; check the manager's network status.",
                    }),
              ),
            ),
        }),
      )
      .pipe(Effect.orDie)
  }),
}
