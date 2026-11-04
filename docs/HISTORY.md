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

## Managed handoff contract for 1.0

Different conversations and agents may run concurrently inside one Safe.
Moving the same conversation to another agent is a managed handoff: verify
that the previous client and its backend writers stopped, reconcile saved
history, update the inactive target profile, resolve its native ID, then open
that ID in the official client. The saved task is not submitted again.

The first version requires the destination profile to be inactive during
projection. A busy profile or uncertain backend lifetime blocks the handoff
until work finishes or explicit recovery succeeds. Other conversations are
not automatically stopped. These lifecycle and continuation steps remain
under implementation and qualification.

Native arguments, pickers and plugins stay available. Universal exclusion of
all manual same-chat mutations is outside this 1.0 contract. The supported
handoff must report its actual busy/recovery state rather than claim that a
closed terminal proves an idle backend.

## Admission coverage and remaining work

This is prompt admission, **not a complete single-author guarantee**. Claude's
native `/compact` command bypasses `UserPromptSubmit`; even a denied
`PreCompact` writes local command transcript rows in the pinned version.
Interactive picker mutations, background continuations and other native
mutation paths remain outside that coverage. The 1.0 handoff contract above
does not claim universal interception of those paths.

Codex and OpenCode prompt admission is not integrated. Codex's pinned hook
execution errors fail open and its shared backend does not expose the
attaching TUI's owner to those hooks. OpenCode's pinned prompt hook lacks a
supported denial result and frontend owner. Their public local control
protocols offer bounded integration seams. Codex's pinned `exec` and `review`
paths use an in-process backend and reject `--remote`; see the
[native executor](https://github.com/openai/codex/blob/ff6aec96948b70d94983af2641a6b67c94faeff5/codex-rs/exec/src/lib.rs#L986).
OpenCode's external-server mode changes managed reconnect and environment
forwarding, while plugins can invoke core Session methods directly; see
[frontend startup](https://github.com/anomalyco/opencode/blob/afc3359eda634d9df012df5fe599e6bbfe26a655/packages/cli/src/commands/handlers/default.ts#L59-L101)
and [plugin methods](https://github.com/anomalyco/opencode/blob/afc3359eda634d9df012df5fe599e6bbfe26a655/packages/core/src/plugin/host.ts#L505-L530).
Redirecting a TUI through a relay therefore needs an explicit supported-mode
contract before it can provide complete ownership. The launcher currently
forwards native arguments unchanged. A shared environment nonce or post-hoc
watcher does not provide full writer enforcement.

Backend lifetime also needs separate tracking: Codex's detached daemon can
retain threads after a frontend exits. A wrapper's profile flock alone cannot
establish that every writer has stopped. Projection safety and a reliable
cross-agent handoff require actual backend shutdown or retained authority.

Focused Linux socket/process tests and offline tests with the actual pinned
Claude binary pass without a provider or model call. Safe-wide shutdown,
power loss and verified cross-agent handoff still require qualification.
Implementation and fixture commands are in
[the history package](../packages/oblivion-history/README.md).
