# Experimental shared histories — outside the 1.0 scope

The shared conversation catalog, cross-agent projections and handoff are not
part of Oblivion 1.0. Each official agent keeps its own native chat history and
resume. This document describes the existing experimental package; its runtime
removal or disconnection is pending code work. Updating this file does not
disable the watcher or hooks.

This package synchronizes a Safe's conversation catalog into the current native histories of Codex 0.159.2, Claude Code 2.1.302 and OpenCode 2.0.1. It uses Python 3.11 or newer and the standard library. It runs inside the Safe and receives explicit home, workspace and catalog paths.

The catalog stores stable chat identities, per-agent native identities, ordered typed content, native item mappings and source revisions in SQLite. Native-only facts include provider reasoning, signatures, compaction and interrupted records. Exact source bytes are reconstructed from compressed record chunks and revision deltas, so append-heavy histories share their unchanged records. Files and SQLite journals belong on the Safe's encrypted volume. The sync lock serializes reconciliation. JSONL files use atomic replacement and fsync. OpenCode's official importer initializes its current database, and subsequent inactive updates use a transaction over its message projection and aggregate sequence.

Codex uses the current paginated rollout format, with explicit ordinals and native completed-item records. The adapter registers names through the pinned native app-server. It reads visible conversation items from completed native records and retains the full model context separately in the source snapshot. It preserves an existing rollout's path and session metadata when incorporating another client's follow-up.

Claude uses the current JSONL parent chain and custom-title records. OpenCode uses its `session_v2` and `session_message` schema. The source transcript is retained byte-for-byte when it already contains the complete canonical conversation. Unknown formats generate an error and fence writes to that client's profile.

For runtime status and reconciliation, query the Safe’s fixed-root watcher. Its Unix socket accepts only a versioned sync request and checks the caller UID. It returns bounded counts, pending agent identifiers and retention notices.

```sh
python3 /usr/lib/oblivion/history/history.py sync \
  --sync-socket /run/oblivion-history/sync.sock
```

For an isolated development fixture, run one reconciliation directly.

```sh
python3 /usr/lib/oblivion/history/history.py sync \
  --home /vault/home \
  --workspace /vault/workspace \
  --state /vault/home/.oblivion-history
```

The guest installs `oblivion-history.service` and starts one notify-ready watcher after mounting the vault. Native indexers and imports run inside its private network namespace. The official OpenCode importer needs a loopback HTTP server, so the watcher permits AF_UNIX and private loopback networking with external addresses denied. The user’s actual native client runs in the Safe’s normal controlled network namespace.

The standalone watcher command is equivalent to the service entry point.

```sh
python3 /usr/lib/oblivion/history/history.py watch \
  --home /vault/home \
  --workspace /vault/workspace \
  --state /vault/home/.oblivion-history \
  --sync-socket /run/oblivion-history/sync.sock \
  --admin-socket /run/oblivion-history/admin.sock \
  --interval 2
```

Wrap each native client so a synchronizer can avoid rewriting that client's active profile.

```sh
python3 /usr/lib/oblivion/history/history.py hold \
  --home /vault/home \
  --workspace /vault/workspace \
  --state /vault/home/.oblivion-history \
  --sync-socket /run/oblivion-history/sync.sock \
  --group-signals --agent codex -- codex resume
```

Runtime `hold` requests reconciliation through the watcher before and after the native process. It does not invoke indexers or importers in the client’s online namespace. `--group-signals` matches the guest channel and PTY contract, where the native client already receives the original process-group signal. It prevents a duplicate Ctrl+C. Standalone direct reconciliation remains available for isolated fixtures. Its shared flock exists only while the process runs, including across multiple clients using the same profile. The writer requires an exclusive lock. An active profile can still be read, and the other inactive profiles receive its saved work. stdin, stdout and stderr remain connected to the native client. Its exit status and signals are preserved.

The Safe’s guest startup installs the package, starts the watcher after unlocking storage and wraps each launcher. Guest shutdown stops the watcher before unmounting. The package does not inspect profiles on the physical host. It does not itself provide controller authorization or a cross-Safe endpoint.

User/assistant text, settled text tool calls/results, embedded images and native file attachments enter the canonical catalog. PDF attachments project to Claude and OpenCode. Codex retains them in the encrypted archive because its native user-input format cannot represent a general document attachment. Other unsupported attachment formats and binary tool content produce explicit retention notices.

Provider-owned reasoning and signatures are never synthesized for another agent. Compaction and interrupted native records remain exact source facts. When the existing visible transcript is a prefix of the canonical conversation, a foreign follow-up appends to that native prefix without altering its signed blocks, compaction boundaries or other native records. When an edited transcript needs reconstruction, incompatible native facts remain in the encrypted archive and the sync report identifies what its portable projection omits. No placeholder answer or invented summary is added to the conversation.

`sync` returns per-target `retained` entries that identify the fact kind, count and whether it is present natively or retained only in the encrypted archive. Runtime `hold` emits a short English notice on stderr when material cannot accompany that agent’s portable history. Source facts do not prevent ordinary text/tool conversations from being resumed. Unknown file formats still fail explicitly.

Native paths honor the guest environment when the requested home matches process HOME. In the shipped guest, config is `/vault/config`, native data and state are `/vault/state`, cache is `/tmp/oblivion-cache`, Codex is under `/vault/home/.codex` and Claude is under `/vault/home/.claude`. `--data-home`, `--config-home`, `--cache-home`, `--native-state-home`, `--codex-home` and `--claude-home` make fixture roots explicit. A different supplied home ignores ambient host profile paths. The catalog’s own `--state` directory is distinct from native XDG state.

The shared process lease prevents rewriting an active agent profile. Claude also has the prompt-admission service described below; complete chat-level admission for every client and native mutation was not qualified by this prototype and is outside the 1.0 scope. Projection intents and identity mappings commit before native storage changes. An interrupted projection fences ingestion from that profile and replays on the next reconciliation before the intent is cleared. The launcher refuses to start a client whose profile still needs projection recovery. Native metadata changes also retain the last observed title and item digests so stale copies cannot overwrite a rename or edit made elsewhere. These paths were checked with a deliberately interrupted projection and a stale metadata update. Full process-death and power-loss acceptance remains to be qualified in the VM.

Explicit catalog deletion uses a separate UID-bound administration socket. `list` returns at most 200 chat identifiers, bounded titles and timestamps; it never returns messages. Copy the exact canonical identifier into both deletion arguments. Native IDs and title aliases are not accepted as confirmation.

```sh
python3 /usr/lib/oblivion/history/history.py list \
  --admin-socket /run/oblivion-history/admin.sock
python3 /usr/lib/oblivion/history/history.py delete \
  --admin-socket /run/oblivion-history/admin.sock \
  --chat 00000000-0000-0000-0000-000000000000 \
  --confirm 00000000-0000-0000-0000-000000000000
```

Deletion refuses while any client profile lease is active. Confirmation commits a tombstone before native storage changes. The watcher retries unfinished native removals and fences the affected profiles until they succeed. Codex uses its supported `thread/delete` RPC; OpenCode uses its supported `session delete --standalone` command and refuses an execution claim in the chat or its children. Claude has no supported deletion RPC in the pinned version: this explicitly confirmed operation verifies the transcript's native ID, workspace and current format before removing that transcript and its session-specific sidecar directory. On successful completion the catalog removes the conversation items, native facts and archived source chunks, retaining the minimal deletion identity. This is logical removal from the managed histories, not a guarantee of physical erasure from storage snapshots or external backups.

Missing files, partial JSONL records and absent database rows never create a tombstone. A previously deleted transcript restored from a stale native backup cannot recreate the canonical chat; it is queued for removal again. Deletions made directly inside native pickers are **not** automatically treated as cross-agent deletion. Codex's deletion notification is transient and no supported Claude deletion event was found; OpenCode's durable deletion event still needs a pinned-client integration. Guessing from disappearance would also mistake incomplete reads and manual moves for deletion. Focused checks used the actual pinned Codex/OpenCode deletion APIs and covered missing-file safety, busy clients, mismatched confirmation, restored stale data and replay after durable confirmation.

Claude 2.1.302 prompt admission uses a mandatory managed `UserPromptSubmit` hook with `onFailure: block`. The independent `oblivion-author.service` resolves native IDs through the canonical catalog. A wrapper is registered through `SO_PEERCRED` and `SO_PEERPIDFD`; its actual child is pinned before native execution, with checked ancestry/starttime. A claim must come from that child's process tree. The canonical lease lasts through native exit and the wrapper's final reconciliation. A killed wrapper cannot release a still-running native writer: the daemon terminates the pinned child and waits for its actual exit. Distinct canonical chats can hold leases concurrently. A stale foreign projection is denied with a reopen notice rather than rewritten behind an active client's profile lease.

Active markers contain identities, never prompt text, and remain on the encrypted Safe volume. If the daemon unexpectedly restarts in the same guest boot with an active marker, admission stays fenced until the Safe is closed and reopened. Losing a flock never proves that its native writer stopped. A different guest boot can clear the previous boot's markers. Safe-wide VM shutdown and power-loss behavior still need hardware acceptance.

This is **Claude prompt admission**, not complete native single-author enforcement. Native `/compact` bypasses `UserPromptSubmit`. In the pinned client, a blocking `PreCompact` hook stops compaction but still adds local command transcript rows; it is not installed as a substitute for full ownership. Codex exposes synchronous prompt hooks, but execution errors fail open and its shared backend lacks an attached-TUI owner identity. OpenCode 2.0.1's public `session.prompt` hook lacks a client owner and supported policy-denial result. Codex/OpenCode admission was not integrated; further relay and mutation-coverage work is outside the 1.0 scope. A wrapper environment nonce alone cannot identify a later terminal attached to a persistent backend.

The actual pinned-Claude fixture checks concurrent `--resume`, mandatory hooks under `disableAllHooks`, `--bare` and `CLAUDE_CODE_SIMPLE`, and missing/crashed/invalid-structured-output/timed-out hooks. Every tested prompt is denied with zero model calls and no canonical user message; native queue/system metadata may still be written. Run `sh tests/claude-author-native.sh IMAGE AGENTS_DIRECTORY` with an existing Linux fixture image and pinned official agent binaries. Docker has no external network; all profiles and inputs are synthetic. The ordinary `test_author.py` suite checks real Linux process pins, orphan cleanup, canonical alias exclusion, distinct-chat admission and restart fencing. Its Linux-only cases intentionally skip on macOS.

Primary interfaces checked: [Codex pinned prompt hooks](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/hooks/src/events/user_prompt_submit.rs), [Codex managed hook trust](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/hooks/src/engine/discovery.rs), [Claude hook control](https://code.claude.com/docs/en/hooks), [OpenCode 2.0.1 prompt hooks](https://github.com/anomalyco/opencode/blob/v2.0.1/packages/plugin/src/promise/session.ts).

Native reader checks used isolated profiles and localhost fixture providers. A real Codex command/tool transcript was resumed in real Claude with the original tool input and result present in the provider request. Claude's follow-up appeared in OpenCode's native list/export and back in Codex's paginated resume, including a visible native dynamic tool item. Repeating reconciliation produced no writes. A focused portability check also retained synthetic thinking/signature bytes and compaction exactly, projected a PDF through an explicit XDG data root and appended a foreign follow-up without changing its source prefix. These prototype checks did not qualify interactive cross-agent pickers, all six directions, process-death recovery, provider acceptance for attachments or two-Safe operation. Cross-agent checks are outside 1.0; native persistence, shutdown and isolation still need product acceptance.

The Codex format was checked against the pinned implementation. [Codex item definitions](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/protocol/src/items.rs), [native dynamic tool content](https://github.com/openai/codex/blob/rust-v0.159.2/codex-rs/protocol/src/dynamic_tools.rs).

Portable Share uses a separate current-only JSONL format through
`oblivion_history.portable`. It exports explicitly selected canonical chat and
item identities, ordered visible content and titles. It omits native IDs,
provider reasoning/signatures, raw native records, projection state and login
profiles; omission counts accompany the review. Tool call/result identities
remain paired. Working directories carry a `workspace` or `imports` scope and
a relative path, so an import binds them to the destination Safe rather than
retaining a source path. Outside paths are rejected. Attachment URLs remain
data and are never fetched during import.

Export reads the catalog without starting a watcher, native importer, server or
agent, and requires exclusive reconciliation/profile leases. Import accepts a
new empty catalog only: existing canonical identities are never merged or
overwritten. It creates declared empty working directories and canonical rows;
native histories are generated later when the user explicitly launches a
client. The portable catalog limit is 256 MiB, with at most 2,048 selected
chats, 100,000 items and 16 MiB per JSONL record. No native source archive is
included as a substitute for an omitted item.

The guest Share planner streams selected `workspace`/`imports` files directly
through the existing hash-verified transfer manifest. Only generated portable
history is staged inside the encrypted source Safe. Sensitive-file/chat
detection is a bounded best-effort review aid; it excludes candidates by
default and never claims to remove arbitrary secrets from conversation text.
The focused fixtures run with `python3 -m unittest discover -s tests -p
'test_*.py'` from this package. Linux fixtures also exercise the actual compiled
copy endpoint when `OBLIVION_COPY_TEST_BINARY` points to `oblivion-copy`.


Safe administration reuses `oblivion_history.admin.catalog_state` for a bounded,
read-only SQLite snapshot of the current v1 catalog, including committed WAL
records. The local admin RPC exposes `catalog-state` with a canonical UUID
cursor; SafeAdmin can call the same pure function during offline maintenance
without starting the watcher, any importer, or a native agent/server. Pages
contain at most 50 canonical IDs, sanitized titles, timestamps and agent names;
no message, native profile path, credential or source payload is returned.
Tombstones are excluded. A missing catalog means `catalog-empty` and creates
nothing. A present invalid or unsupported catalog fails instead of being reset.
`catalog-sqlite-ok` describes the catalog's SQLite integrity only; it is not a
claim that every native transcript has been semantically verified.
