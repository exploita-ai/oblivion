import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

// Compile both real variants and use a live local OTLP endpoint as a positive
// control: absence of requests alone could also mean a broken test endpoint.
test("compiled Oblivion disables logs, OTLP and heap snapshots despite environment overrides", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "oblivion-observability-"))
  const requests: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      await request.arrayBuffer()
      requests.push(new URL(request.url).pathname)
      return Response.json({})
    },
  })
  try {
    const results = await Promise.all(
      [true, false].map(async (profile) => {
        const directory = path.join(root, String(profile))
        await fs.mkdir(directory)
        const build = await Bun.build({
          entrypoints: [path.join(import.meta.dir, "fixture/oblivion.ts")],
          outdir: directory,
          target: "bun",
          define: { OBLIVION_PROFILE: JSON.stringify(profile) },
        })
        expect(build.success, build.logs.map(String).join("\n")).toBe(true)
        const child = Bun.spawn(
          [process.execPath, path.join(directory, "oblivion.js"), path.join(directory, "heaps")],
          {
            cwd: directory,
            env: {
              PATH: process.env.PATH,
              HOME: directory,
              XDG_DATA_HOME: path.join(directory, "data"),
              XDG_CONFIG_HOME: path.join(directory, "config"),
              XDG_STATE_HOME: path.join(directory, "state"),
              XDG_CACHE_HOME: path.join(directory, "cache"),
              TMPDIR: directory,
              TEMP: directory,
              OBLIVION_PROFILE: String(!profile),
              OPENCODE_PRINT_LOGS: "1",
              OPENCODE_LOG_LEVEL: "DEBUG",
              OTEL_EXPORTER_OTLP_ENDPOINT: `${server.url.origin}/${profile}`,
            },
            stdout: "pipe",
            stderr: "pipe",
          },
        )
        const [stdout, stderr, code] = await Promise.all([
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
          child.exited,
        ])
        expect(code, stderr).toBe(0)
        expect(JSON.parse(stdout)).toEqual({ oblivion: profile })
        return { profile, directory, stderr, files: await fs.readdir(directory, { recursive: true }) }
      }),
    )
    const privacy = results[0]
    expect(privacy.stderr).toBe("")
    expect(privacy.files.some((file) => file.endsWith(".log") || file.endsWith(".heapsnapshot"))).toBe(false)
    expect(requests.filter((route) => route.startsWith("/true/"))).toEqual([])
    expect(requests).toContain("/false/v1/traces")
    expect(results[1].stderr).toContain("OBLIVION_LOG_TEST_CANARY_2dc9")
    const log = results[1].files.find((file) => file.endsWith(".log"))
    expect(log).toBeDefined()
    expect(await Bun.file(path.join(results[1].directory, log!)).text()).toContain("OBLIVION_LOG_TEST_CANARY_2dc9")
  } finally {
    server.stop(true)
    await fs.rm(root, { recursive: true, force: true })
  }
}, 30_000)
