import { describe, expect, test } from "bun:test"
import { chmod, stat, writeFile } from "node:fs/promises"
import path from "path"
import { Effect, Layer } from "effect"
import { sql } from "drizzle-orm"
import { Database } from "@opencode/core/database/database"
import { Global } from "@opencode/util/global"
import { tmpdir, tmpdirScoped } from "./fixture/tmpdir"
import { it } from "./lib/effect"

it.live(
  "syncs WAL commits on every connection and recovers the committed data on reopen",
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped()
    const filename = path.join(tmp.path, "oblivion.db")
    yield* Effect.forEach([false, true], (reopen) =>
      Effect.gen(function* () {
        const database = yield* Database.Service
        expect(yield* database.db.get(sql`PRAGMA journal_mode`)).toEqual({ journal_mode: "wal" })
        expect(yield* database.db.get(sql`PRAGMA synchronous`)).toEqual({ synchronous: 2 })
        if (!reopen) {
          yield* database.db.transaction((tx) =>
            Effect.gen(function* () {
              yield* tx.run(sql`CREATE TABLE _durability_probe (message text NOT NULL)`)
              yield* tx.run(sql`INSERT INTO _durability_probe VALUES ('committed chat content')`)
            }),
          )
        }
        expect(yield* database.db.all(sql`SELECT message FROM _durability_probe`)).toEqual([
          { message: "committed chat content" },
        ])
      }).pipe(
        Effect.provide(Database.layer({ path: filename })),
        Effect.provideService(Global.Service, Global.make({ data: tmp.path })),
        Effect.scoped,
      ),
    )
  }),
)

// Read while the connection is open: SQLite may remove the sidecars on close.
const openModes = (filename: string) =>
  Effect.runPromise(
    Effect.gen(function* () {
      yield* Layer.build(Database.layer({ path: filename }))
      return yield* Effect.promise(() =>
        Promise.all(["", "-wal", "-shm"].map(async (suffix) => (await stat(filename + suffix)).mode & 0o777)),
      )
    }).pipe(Effect.scoped, Effect.provideService(Global.Service, Global.make({ data: path.dirname(filename) }))),
  )

describe.skipIf(process.platform === "win32")("Database file permissions", () => {
  test("creates the database and sidecars readable only by the owner", async () => {
    await using tmp = await tmpdir()

    expect(await openModes(path.join(tmp.path, "opencode.db"))).toEqual([0o600, 0o600, 0o600])
  })

  test("tightens an existing database and sidecars", async () => {
    await using tmp = await tmpdir()
    const filename = path.join(tmp.path, "opencode.db")
    await Promise.all(
      ["", "-wal", "-shm"].map(async (suffix) => {
        await writeFile(filename + suffix, "")
        await chmod(filename + suffix, 0o644)
      }),
    )

    expect(await openModes(filename)).toEqual([0o600, 0o600, 0o600])
  })
})
