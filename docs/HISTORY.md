# Native history and conversation admission

Safes retain one encrypted conversation catalog and separate native histories
for Codex, Claude Code and OpenCode. The catalog maps their native IDs to a
canonical conversation ID. It preserves source records and provider-owned
facts without inventing another provider's reasoning or signatures. Native
clients keep their own authentication and UI.

The watcher reconciles saved history and updates inactive native profiles.
Running clients hold a shared profile lease so the watcher cannot replace
their files. An already open client may therefore need to be closed and
reopened to receive another agent's follow-up. A profile lease prevents
concurrent rewrites; it is not conversation ownership.

## Claude prompt admission

The current implementation adds a separate Safe-local admission service for
Claude Code 2.1.302's `UserPromptSubmit` hook. It checks ownership **before a
prompt reaches the model**. A conversation already claimed by another native
process is denied. Different conversations remain concurrent. A stale local
projection is denied with an instruction to reopen the agent.

The native process is pinned before execution. Linux peer credentials and
peer pidfds bind the launcher identity; ancestry, process starttime and a
child pidfd bind the actual native writer. Hook subprocesses cannot replace
that identity with their own PID. The service resolves canonical IDs from the
catalog rather than accepting a caller-supplied conversation ID.

The lease covers native execution and the wrapper's final reconciliation. If
the wrapper dies while its native child survives, the service terminates that
pinned child and retains ownership until it exits. An unexpected admission
service restart with active same-boot markers fences new admissions. Close
and reopen the Safe to recover; restarting the service is not proof that the
old writer stopped. Markers contain process and conversation identities, not
prompt content, and belong to the encrypted Safe.

The hook is installed in Claude's managed settings and uses `onFailure: block`.
User hooks and provider settings remain separate. Pinned-client checks verify
that `disableAllHooks`, `--bare` and `CLAUDE_CODE_SIMPLE` do not disable this
managed hook. A denied prompt can leave native queue or system metadata, but
does not become a canonical user message in the tested cases. This is not a
boundary against a user deliberately modifying the Safe's root-owned policy
with its own sudo access.

## Remaining release gates

This is prompt admission, **not a complete single-author guarantee**. Claude's
native `/compact` command bypasses `UserPromptSubmit`; even a denied
`PreCompact` writes local command transcript rows in the pinned version.
Interactive picker mutations, background continuations and all other native
mutation paths need a complete admission boundary before that claim is made.

Codex and OpenCode prompt admission is not integrated. Codex's pinned hook
execution errors fail open and its shared backend does not expose the
attaching TUI's owner to those hooks. OpenCode's pinned prompt hook lacks a
supported denial result and frontend owner. Their public local control
protocols are the next integration seam, preserving official binaries and
native TUIs. No shared environment nonce or post-hoc watcher is treated as
full writer enforcement.

Focused Linux socket/process tests and offline tests with the actual pinned
Claude binary pass without a provider or model call. Safe-wide shutdown,
power loss and complete cross-agent ownership still require qualification.
Implementation and fixture commands are in
[the history package](../packages/oblivion-history/README.md).
