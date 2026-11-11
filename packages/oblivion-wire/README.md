# Oblivion private wire

Platform-independent request data and bounded byte framing for Oblivion's private
controller and agent channels. Linux, macOS and Windows frontends use one
control vocabulary. The crate contains no sockets, filesystem access, terminal
APIs, VM discovery or operating-system dependencies.

The local controller accepts a u32 big-endian JSON length and a header of at most
1024 bytes. The desktop relay adds `version: 1`; its JSON response is independently
length-framed and bounded at 1 MiB. The local controller response ends at EOF.
Secrets follow the request header as separate bytes. Peer authentication,
operation authorization, per-operation secret budgets and sanitized errors belong
to the host/controller, outside this crate.

Agent channels retain their existing kind byte, u32 big-endian payload length and
at most 65536 raw payload bytes; empty payloads remain valid for stdin EOF. Size
is the shared guest PTY geometry. Agent launch admission, managed jobs, file
manifests and OS-specific byte transport retain their domain/platform owners.
Launch requests and the incremental frame decoder are shared here.
Agent output frames carry nonempty stdout/stderr data. A relay failure ends the
stream with kind 7 and an empty payload, separate from the agent's kind-4 exit
status. The former empty-stderr/exit-125 marker is rejected. Controller headers
always include their slot, and controller status always includes recovery
observations; missing values are not inferred from an older payload.

The private runtime bootstrap has one current v2 format: READY, the per-boot
token, bounded Existing/NewDisk metadata and SET. NewDisk carries only an exact
runtime identity and capacity; the host adapter owns authorization from fresh
SDK creation or the exact protected Pending setup receipt.
There is no disk pathname or compatibility reader in this protocol. Control
connections retain their separate HELLO/token/ACK exchange.

From this directory:

```sh
cargo test --locked
cargo check --locked --lib --target x86_64-pc-windows-msvc
```

Windows compilation verifies this portable layer only. The Windows CLI and
Hyper-V runtime live in their platform packages; their installed integration,
encrypted disk provisioning and terminal behavior require separate
qualification. See [the Windows backend](../../docs/WINDOWS.md).
