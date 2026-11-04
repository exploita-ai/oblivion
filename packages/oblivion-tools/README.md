# Oblivion native tools

A local stdio MCP server for the official Codex, Claude Code and OpenCode2 clients inside a Safe.

- `tor_rotate` rotates only the current Safe's Tor route.
- `safe_status` reads the current Safe's identity, closing state, creation limits and paginated child records.
- `safe_create` creates a separate encrypted child Safe and schedules its requested official agent/task once. Only that agent's supported credential is handed over through a private sealed channel; no files or unrelated profiles are copied. Missing or unsupported authentication produces `delivery: needs-auth`, without anonymous startup. The creation record's `awaiting-start` state is separate from nullable controller observations: queued/preparing, submitted, finished or unavailable. Submission means admission; the observed job state determines the actual outcome.
- `chat_create` admits a managed conversation using an official agent in the current Safe, sharing its files and existing agent login. `queued` confirms admission only. Authentication and permission prompts are not bypassed.
- `chat_status` reads job metadata by exactly one `job_id` or creation `request_id`, without starting or resuming an agent.
- `chat_cancel` requests cancellation of one managed job. Only a returned `cancelled` state confirms cancellation; other states require another status check.

The Safe tools appear only after a valid capabilities handshake with the trusted local bridge at `/run/oblivion-safe-tools.sock`. The controller determines the parent Safe and its family authority; the caller cannot supply a parent, slot or password. Persistent child Safes share their family's unlock password while retaining separate encrypted volumes. An ephemeral parent creates an ephemeral RAM-only child, discarded on branch or host lock. The controller attests `created_by_agent`; `creator_chat_id` is caller-reported metadata. A missing or invalid bridge leaves those tools unavailable.

The bridge uses bounded 24 KiB frames, a new RPC request ID for every invocation and no automatic retries. Each reply must match its request ID. An interrupted Safe creation, including the controller's explicit unknown-outcome response, is reported as unconfirmed with that ID, so the agent can inspect `safe_status` instead of creating duplicate children.

Managed chat creation also has a separate idempotency `request_id`, generated once when omitted. An unconfirmed creation must be looked up with `chat_status({ request_id })`; it must not be replayed automatically. Job replies contain only IDs, agent, state, native chat ID and a bounded failure reason. Prompts and output remain inside the Safe. These jobs do not reset human-activity timers and stop when their Safe is locked. Status, creation and cancellation have client deadlines of 10, 165 and 20 seconds respectively; the controller bounds its workers separately. The local bridge calls do not use the external network; a managed agent may use the Safe's configured gateway.

The current controller allows one managed job at a time and at most 16 retained job records per Safe. Each job has a 30-minute deadline and a combined 4 MiB stdout/stderr quota. Task text, raw output and the status manifest live only under `/vault/home/.oblivion-jobs/<job_id>/`, inside that Safe's encrypted filesystem or ephemeral RAM. Tasks are limited to 16 KiB and must also fit the bridge's encoded frame limit. A repeated creation request ID returns the original job without replacing its task. Status lookup after reopening reads its manifest; it never restarts interrupted work.

Managed invocations use the pinned clients' official headless modes: Codex `exec --json`, Claude `--print --output-format stream-json`, and OpenCode2 `run --standalone --format json`. They do not enable automatic approvals or sandbox bypasses. Requests requiring approval/input are denied by the native noninteractive path and reported as `needs-input` when observed. A native authentication error becomes `needs-auth`; an inconclusive startup/network wait becomes `timeout`, rather than a guessed authentication failure. Configure the target client interactively inside the same Safe when needed. A failure of confirmed process/lease cleanup fences the opening for recovery.


`tor_rotate` takes no arguments. It calls the Safe's fixed private rotation endpoint, using the current opening's capability from RAM. The gateway closes application traffic before rotating Tor, verifies isolation before reopening it, and keeps traffic blocked when rotation fails. Rotation interrupts every active model request, download and TCP connection in that Safe. It does not guarantee that a website will accept the next exit.

The server has a 160-second deadline, a bounded response size and no automatic retry. It does not accept URLs or provider credentials, retain tokens, write logs, or use external proxy environment variables for the private gateway request. Unconfirmed responses report an error; they do not claim that rotation succeeded.

## Image integration

Build from the repository root:

```sh
bun run --cwd packages/oblivion-tools build
```

Install the output as `/usr/lib/oblivion/tools/server.mjs`, alongside the image's pinned Node runtime at `/usr/lib/oblivion/node/bin/node`.

The guest configuration files live in `packages/oblivion-host/guest/native-tools`:

- Install `codex.toml` as `/etc/codex/config.toml`. This uses Codex's system configuration layer and leaves the Safe's native user configuration intact.
- The Claude and OpenCode2 launch profiles run `configure.py` before launching their native executable. It adds the local server to `.claude.json` or the XDG OpenCode configuration. Updates are serialized and atomic within the encrypted profile directory. Existing providers, other MCP servers and an existing `oblivion` entry remain unchanged, including disabled entries.
- OpenCode2 uses `mcp.servers.oblivion`, `codemode: false` and separate startup, catalog and execution timeouts. The v1 OpenCode MCP configuration shape is different.

All three clients retain their original argument list. Native client settings and permissions still control whether a tool call is allowed.

## Verification

```sh
cd packages/oblivion-tools
bun test --timeout 30000
bun run typecheck:tsc

cd ../oblivion-host/guest/native-tools
python3 -B -m unittest -v test_configure
```

The tests exercise the real Node bundle's MCP discovery and strict argument rejection, closed response validation, and preservation of native profiles. A local Unix relay fixture checks scoped Safe requests, managed job metadata, exclusive status lookups, creation uncertainty and reconciliation without retries, cancellation, and malformed handshakes. They do not invoke Tor rotation, create real encrypted volumes or start real agent jobs. The controller/guest bridge and managed jobs still need a real VM integration test.

The pinned Linux ARM64 clients were also checked in an isolated container with networking disabled and fresh HOME/XDG directories: Codex 0.159.2 loaded the system MCP configuration, Claude Code 2.1.302 connected to the stdio server, and OpenCode2 2.0.1 connected after its asynchronous service initialization. A gateway/VM integration test remains necessary to verify actual traffic isolation and rotation outcomes.

Client configuration references: [Codex MCP](https://developers.openai.com/codex/mcp), [Claude Code MCP](https://code.claude.com/docs/en/mcp), and the pinned OpenCode2 client's native configuration schema.
