import { expect } from "bun:test"
import { Effect, Layer } from "effect"
import { HttpClient, HttpClientResponse } from "effect/http"
import { AppNodeBuilder } from "@opencode/core/effect/app-node-builder"
import { makeLocationNode } from "@opencode/util/effect/app-node"
import { LayerNodePlatform } from "@opencode/util/effect/app-node-platform"
import { LayerNode } from "@opencode/util/effect/layer-node"
import { Tool } from "@opencode/core/tool"
import { TorRotateTool } from "@opencode/core/tool/plugin/tor-rotate"
import { Permission } from "@opencode/core/permission"
import { Session } from "@opencode/core/session"
import { Image } from "@opencode/core/image"
import { testEffect } from "./lib/effect"
import { executeTool, registerToolPlugin, toolDefinitions, toolIdentity } from "./lib/tool"
import { imagePassthrough } from "./lib/image"
import { permissionLayer } from "./lib/permission"
import { withEnv } from "./fixture/env"

const node = makeLocationNode({
  name: "test/tor-rotate",
  layer: Layer.effectDiscard(registerToolPlugin(TorRotateTool.Plugin)),
  deps: [Tool.node, Permission.node, LayerNodePlatform.httpClient],
})
const token = "a".repeat(64)
const operations: string[] = []
let status = "rotated"
let code = 200
const it = testEffect(
  AppNodeBuilder.build(LayerNode.group([Tool.node, node]), [
    Image.node.replace(imagePassthrough),
    Permission.node.replace(
      permissionLayer({
        assert: (input) =>
          Effect.sync(() => {
            operations.push("authorize")
            expect(input.action).toBe("tor_rotate")
            expect(input.resources).toEqual(["current-protected-session"])
            expect(input.source).toMatchObject({ type: "tool", id: "rotate-call" })
          }),
      }),
    ),
    LayerNodePlatform.httpClient.replace(
      Layer.succeed(
        HttpClient.HttpClient,
        HttpClient.make((request) =>
          Effect.sync(() => {
            operations.push("request")
            expect(request.url).toBe("http://10.88.0.1:8114/tor/rotate")
            expect(request.method).toBe("POST")
            expect(request.headers.authorization).toBe(`Bearer ${token}`)
            return HttpClientResponse.fromWeb(
              request,
              Response.json(status === "blocked" ? { status, phase: "tor_information" } : { status }, { status: code }),
            )
          }),
        ),
      ),
    ),
  ]),
)

const call = {
  sessionID: Session.ID.make("ses_rotation"),
  ...toolIdentity,
  call: { type: "tool-call" as const, id: "rotate-call", name: "tor_rotate", input: {} },
}

it.effect("exposes a native tool, authorizes before control traffic and filters denied tools", () =>
  withEnv({ OBLIVION_API_TOKEN: token }, () =>
    Effect.gen(function* () {
      operations.length = 0
      status = "rotated"
      code = 200
      const tools = yield* Tool.Service
      expect((yield* toolDefinitions(tools)).some((tool) => tool.name === "tor_rotate")).toBe(true)
      expect(
        (yield* toolDefinitions(tools, [{ action: "*", resource: "*", effect: "deny" }])).some(
          (tool) => tool.name === "tor_rotate",
        ),
      ).toBe(false)
      expect(yield* executeTool(tools, call)).toMatchObject({ status: "completed", output: { status: "rotated" } })
      expect(operations).toEqual(["authorize", "request"])
    }),
  ),
)

it.effect("keeps failures distinct and never reports a blocked rotation as success", () =>
  withEnv({ OBLIVION_API_TOKEN: token }, () =>
    Effect.gen(function* () {
      const tools = yield* Tool.Service
      for (const value of [
        "blocked",
        "tor_required",
        "cooldown",
        "rotation_not_allowed",
        "rotation_in_progress",
        "controller_unavailable",
        "unauthorized",
        "invalid-response",
      ]) {
        operations.length = 0
        status = value
        code = 503
        const result = yield* executeTool(tools, call)
        expect(result.status).toBe("error")
        expect(JSON.stringify(result)).not.toContain(token)
        expect(operations).toEqual(["authorize", "request"])
        if (value === "blocked") expect(JSON.stringify(result)).toContain("remains blocked")
      }
    }),
  ),
)

it.effect("does not contact the gateway without a valid local capability", () =>
  withEnv({ OBLIVION_API_TOKEN: undefined }, () =>
    Effect.gen(function* () {
      operations.length = 0
      const tools = yield* Tool.Service
      expect((yield* executeTool(tools, call)).status).toBe("error")
      expect(operations).toEqual(["authorize"])
    }),
  ),
)
