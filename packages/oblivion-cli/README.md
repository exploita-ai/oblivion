# Portable Oblivion frontend

The native launcher consumes the shared command parser and executor in this
crate. `status --json`, `safes` and `close NAME` use one controller read model;
`run` owns Safe lookup, creation or reopening, network configuration, protected
startup and cleanup after a failed attachment. `shell --safe` uses the same
opening, startup and cleanup for tmux. `init`, `unlock`, `ephemeral` and `lock`
share their storage-mode checks, confirmation and controller operations. The Windows frontend consumes
the same implementation without reproducing these decisions.

The frontend uses an injected authenticated controller and platform hooks for
private passwords, human confirmation, available slots, monotonic time,
waiting, notices and terminal attachment. It does not open sockets, configure a
VM, read an OS credential store or manage a terminal itself. Controller-side
authorization remains authoritative; a parsed request does not grant access or
mean a named Safe exists.

Options stop at `codex`, `claude` or `opencode2`. All subsequent UTF-8 strings are
passed unchanged, including empty strings and options with the same spelling as
Oblivion's. The parser neither splits commands nor expands shell expressions.
An omitted transport/policy remains omitted rather than changing an existing Safe.

An existing `--safe` never creates a replacement. An active Safe reuses its slot
and refuses network overrides through `run`; trusted network controls handle
those changes separately. A closed RAM child reopens its existing volume through
its family authority. Calls after opening, including transport changes and idle
cleanup, carry the selected slot and expected Safe identity. A malformed creation
reply is rejected without echoing its contents or using it as a name.

Only `gateway_not_ready` is retried, at 500 ms intervals within a 240-second retry
window. The authenticated transport owns each RPC deadline; this window is not a
hard limit on the total command duration. No direct-network fallback is added.
Attachment failure after a new opening asks the controller to close it only when
idle. A Safe already used by another client is not closed by that failure path.
The shared Workspace executor rejects pipes before issuing controller or password
requests. The launcher rejects malformed Workspace syntax before runtime startup.

Archive creation leaves it locked. Reset only discards a reviewed incomplete
setup and never recreates or unlocks storage. The first new-Safe `run` uses these
same creation and unlock operations. Ephemeral mode cannot replace an open
persistent mode; a global lock addresses the controller without choosing a Safe.

`network status/set` and saved `proxy list/add/remove` use the same frontend too.
Their full syntax, single-change requirement and explicit proxy URLs are checked
before runtime startup or private prompts. Network mutations and their final
status read bind the current Safe and slot. Named-profile listing decodes only
bounded public metadata, with static errors that cannot repeat rejected peer
fields. Private URL and proxy-password entry use the shared completion helper;
adding or removing a saved profile leaves active Safe transports unchanged.

`safe open/rename/grow` and `settings idle` also use shared executors. Offline
opening pins the selected Safe without starting an agent or gateway. Persistent
rename changes catalog metadata even when all VM slots are occupied; temporary
rename stays bound to its active opening. Growth requires closed writable
persistent storage and a free maintenance slot before private password entry.
The size is the requested total capacity in MiB, with actual growth and free-space
checks left to the controller. Automatic-lock updates preserve an omitted timer;
zero explicitly disables it. The preferences and full status view have one wire
model shared with the controller; human-activity and monotonic-clock logic remain
there.

Files `list`, `transfers`, `status`, `recover` and `discard` now use the shared
parser and executor. Safe selection and fresh opening checks are also consumed
by the Unix import/export adapter. Metadata pages and receiver outcomes are
validated before output or recovery; an operation remains bound to its Safe,
slot and opening nonce. The platform adapter owns the private file-channel lease
and local destination filesystem. Trusted source selection, manifest review,
approval and payload streaming for import/export remain in the Unix adapter;
this extraction does not supply Windows filesystem endpoints. Invalid inspection
syntax is rejected by the launcher before it starts the runtime.

`safe task status/review/start/retry/cancel` uses the shared frontend and one
Wire model with the controller. Reviewing a saved task does not start its agent
or gateway. A start keeps the original creation-request identity through protected
startup; uncertain admission is reconciled instead of silently creating a new
attempt. The explicit review response and task use zeroizing storage. Human
output escapes terminal controls; `--json` preserves the native structured view.

`safe password` preview, change, status and recovery share the family DTOs and
workflow too. A change requires the reviewed family digest and current host
opening, private current/new passwords and a human confirmation. Completion and
rollback remain explicit. These operations update wrappers, not data keys, and
cannot revoke old copied headers or backups.

The Windows controller adapter connects to the runtime's private named pipe and
uses the same executors. Its cancellable requests have bounded exchange budgets;
an accepted interactive attachment remains open until cancellation, EOF or a
transport failure. The runtime supervisor must supply the trusted runtime ID.
`windows::Runtime` supplies the actual console/pipe hooks: private password entry,
native guest frames, resize, signals, exact redirected bytes and explicit agent
release before closing its lease. Console presentation uses the same terminal
filter and launch model as Unix. Only human input renews idle activity; bounded
reports carry opening identities, never input content. Installed discovery,
supervisor integration and the command entrypoint are now connected to a per-user
installation registry. The actual installed path is not yet qualified.
Real named-pipe, stdio and isolated-console fixtures are part of the Windows test
target; cross-compilation on Mac does not execute them.

`Runtime::brokered` holds a per-terminal lease from the authenticated SCM broker;
elevated installation alone owns fresh-disk initialization. Ordinary commands
wait for the owned helper's authenticated controller before running common commands.
Another terminal reuses the same runtime. Last-owner idle shutdown is guarded,
and uncertain stop leaves Recovery. Installed discovery verifies one current
bundle, configuration and data identity. The broker owns the privileged runtime
and exposes only typed lifecycle requests; the manager and host file selection
remain unelevated. Installed Windows qualification and owned-resource
reconciliation after losing the supervisor remain unfinished.

`command` owns the complete top-level grammar and help for both native entrypoints.
The Unix copy and Share adapters supply typed parsers before runtime startup;
no command falls through to a second raw-argument dispatcher. The Windows binary
is built explicitly with `--features windows-launcher --bin oblivion` on Windows.
It starts the actual installed manager with a held runtime lease, or runs the
same storage, agent, network, task and administration executors directly.
Status polling and human-activity forwarding read bounded private metadata and
address the existing pipe, without hashing the ISO or booting a stopped runtime.
`runtime start` explicitly starts a resident runtime.

Windows Files connects guest directory pages and receiver metadata through the
opening-scoped file attachment. It releases the client before closing that pipe,
including malformed-response paths. Local payload copies, Share and personal
backup file endpoints, runtime updates/removal and the Live storage selector
are still explicitly unavailable on Windows; these fail before installation
discovery or VM startup. The shared help describes the full product grammar,
not a claim that every Windows endpoint is complete.

Personal backup grammar and `status`, `finish` and `discard` use the common
frontend. The native ciphertext copy engine consumes the same status and finish
operations: a lost final reply is reconciled before another restore can run.
Global reads use the maintenance slot; mutations keep the transaction's recorded
slot. Secret decoding has static errors and zeroizing buffers. Windows local
backup file endpoints remain to be implemented.

SOCKS5 URLs accept the existing literal IPv4/port syntax and optional percent-
encoded credentials. Both `socks5://` and `socks5h://` use the existing transport;
no destination DNS lookup occurs here. A username without `:PASSWORD` returns a
typed `NeedsPassword` request. The platform frontend prompts privately, then
completes and validates it. Secret-bearing requests have no Debug implementation;
decoded buffers and credential values use zeroizing storage, and errors are
static strings without the supplied URL. Explicit credentials supplied in argv
still follow the desktop shell/process trust boundary; parsing cannot erase
those original OS arguments.

From this directory:

```sh
cargo test --locked
cargo check --locked --lib --target x86_64-pc-windows-msvc
# On Windows, link and exercise the actual executable without booting a VM:
cargo build --locked --features windows-launcher --bin oblivion
cargo test --locked --features windows-launcher --test windows_entrypoint
```

The Unix launcher uses this executor in production. Portable compilation and
component tests do not qualify an installed Windows CLI or Hyper-V backend.
