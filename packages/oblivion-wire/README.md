# Oblivion private wire

Platform-independent request data and bounded byte framing for Oblivion's private
controller and agent channels. Linux, macOS and a future Windows frontend use one
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
manifests and OS-specific byte transport remain in their current packages.

From this directory:

```sh
cargo test --locked
cargo check --locked --lib --target x86_64-pc-windows-msvc
```

Windows compilation verifies this portable layer only. It does not provide or
qualify a Windows CLI, Hyper-V runtime, encrypted disk provisioning or terminal
integration; see [the Windows backend plan](../../docs/WINDOWS.md).
