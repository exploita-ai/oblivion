# Portable Oblivion frontend

The native launcher consumes the shared command parser and executor in this
crate. `status --json`, `safes` and `close NAME` use one controller read model;
`run` owns Safe lookup, creation or reopening, network configuration, protected
startup and cleanup after a failed attachment. `shell --safe` uses the same
opening, startup and cleanup for tmux. `init`, `unlock`, `ephemeral` and `lock`
share their storage-mode checks, confirmation and controller operations. The Windows frontend can consume
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
```

The Unix launcher uses this executor in production. Portable compilation and
component tests do not qualify an installed Windows CLI or Hyper-V backend.
