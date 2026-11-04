# Native conversation transfers

Oblivion 1.0 keeps Codex, Claude Code and OpenCode 2 histories independent.
This package only reads each pinned client's native conversation files for
reviewed Share exports and restores them for the same client. It has no common
catalog, background watcher, prompt hook, projection, conversation converter or
cross-agent deletion endpoint.

The current versions are Codex 0.159.2, Claude Code 2.1.302 and OpenCode 2.0.1.
Unknown versions and incomplete transcripts fail explicitly. There are no beta
readers or migration aliases.

`oblivion_history.portable` reads only Codex rollout transcripts and native title
index, Claude project transcripts, and the OpenCode `session_v2` /
`session_message` projections. Source profile configuration, login files, provider
credentials, runtime claims and the sudo overlay are never Share sources. Codex
exports only selected positive thread-index and attachment rows; no native
database file or source-provided SQL is transferred.
Messages can still contain secrets written by users or tools; the guest Share
planner performs bounded best-effort scanning and requires review, rather than
claiming to remove arbitrary secrets.

Each exported conversation retains its original owning agent, version, native
ID, tool names and payloads. Codex/Claude records retain native reasoning and
signatures without converting them to another provider's schema. Codex physical
rollout generations and required immutable prefixes keep exact bytes and paths,
including native byte/ordinal history positions. The native SQLite selected
generation is authoritative; superseded future content is not included merely
because an old file remains. Cold zstd rollouts are bounded-decompressed to the
identical plain bytes. Required inherited prefixes are disclosed in review. Selection UUIDs
are deterministic opaque references derived from agent plus native ID; they are
not persisted in a shared conversation database. Working directories are scoped
to `workspace` or `imports` and rebound to the receiving Safe.

Import validates the complete current-only archive before creating native
profiles in a new unpublished Safe. It refuses existing profiles. Codex and
Claude receive their own transcripts directly, with native Claude subagent/tool
sidecars and referenced file-history backups. Local attachment dependencies must
be explicitly selected in Files; missing, external or provider-only file
references fail clearly rather than producing a broken import. OpenCode receives native
`SessionTransfer.Data` files in encrypted pending storage. On an explicit
OpenCode start, `prepare.py` invokes the immutable official native importer,
parents before children. Codex similarly completes its positive native index
and attachments after the official client initializes the fresh current schema;
source policy overrides are not restored. The preparation path verifies the native ID and saved messages before
removing the transfer; errors retain it for recovery. The offline maintenance VM
does not execute an agent, importer, plugin or user code.

OpenCode's official transfer accepts settled messages. Its unfinished messages
and unsupported native fork provenance are reported as omissions. If the selected
set excludes a native parent, the child is imported as a standalone conversation
and this omitted relationship appears in review. Native tool names, system,
skill, shell and agent/model/location selection messages retain their own format.
The personal raw encrypted backup remains the full-volume recovery option.

Limits: 2,048 conversations, 100,000 native records, 256 MiB per archive and
16 MiB per JSONL record. The Share file manifest, hashes, staging, cancellation
and collection publication remain owned by the existing transfer protocol.

From this package run:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

The Linux channel cases use the actual compiled copy endpoint when
`OBLIVION_COPY_TEST_BINARY` points to `oblivion-copy`; the ownership/import case
also requires root. Fixtures cover native payload and title preservation,
credential exclusion, same-agent restoration, scoped paths, malformed input,
interruption/cancel cleanup and retained failed imports. They do not qualify the
installed clients' interactive pickers or two-device Share; those remain product
acceptance gates.

Pinned primary interfaces: [OpenCode native transfer](https://github.com/anomalyco/opencode/blob/v2.0.1/packages/core/src/session/transfer.ts),
[native import command](https://github.com/anomalyco/opencode/blob/v2.0.1/packages/cli/src/commands/handlers/session/import.ts),
[message schema](https://github.com/anomalyco/opencode/blob/v2.0.1/packages/schema/src/session-message.ts).
