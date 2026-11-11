# Oblivion controller and launcher

The Linux controller manages Oblivion's encrypted archive, independent Safe
VMs, per-Safe gateways and explicit transfer capabilities. The native Rust CLI
uses that same controller through a private relay into a headless Debian VM on
desktop platforms and Debian Live. The controller's authenticated local socket
belongs inside that VM. The OpenTUI manager uses the native launcher interfaces.

This is current 1.0 source under development. Component tests and successful
compilation do not qualify the full installed product. See the
[roadmap](../../docs/oblivion1.0-roadmap.md) for exact remaining acceptance work.

## Storage and lifetime

The general LUKS2 archive contains the application catalog and settings, proxy
profiles and independent Safe LUKS2 files. Each Safe has its own volume key. The
controller mounts only the general filesystem privately with
`nodev,nosuid,noexec`; it does not mount a Safe's filesystem. Only that Safe's VM
mounts the unlocked block device at `/vault`.

A Safe contains the workspace, imports, home, native client profiles and
histories, and the writable system layer used by sudo installations.
Its Debian base remains immutable. Temporary paths use RAM; swap, hibernation,
core dumps and persistent journals are disabled in the managed image.

Multiple Safes can run concurrently, subject to resource admission and a fixed
slot limit. Multiple agents in the same Safe reuse its VM and gateway. Each
opening has an identity and nonce: late cleanup from an old opening must not
close a replacement opening using the same Safe ID and slot.

RAM-only mode enters without opening the general archive and does not borrow
its saved credentials. Read-only archive access is a separate explicit mode.
Do not describe these modes as interchangeable. Desktop runtime disk metadata
can still change while the VM runs; the launcher does not control the outer
OS's swap, snapshots or terminal history.

Close and Lock revoke access, stop owned operations, verify VM termination and
remove the mapping. Busy or unconfirmed cleanup remains a recovery state. There
is no lazy-unmount success path. Host and Safe inactivity timers accept human
input activity only; model output does not renew them.

## Agents and authentication

The guest runs pinned, unmodified Codex, Claude Code and OpenCode 2 binaries.
Native arguments are passed as structured argv. Official client authentication
and saved credentials remain in the Safe's encrypted home. No provider-key
broker or modified OpenCode chat server is part of the current architecture.

Each official client owns its history and native resume. The
[native-history adapter](../oblivion-history/README.md) reads and restores those
formats only for reviewed Share transfers; there is no common conversation
catalog or history watcher. Managed jobs have a separate process lifecycle.
The optional scoped MCP bridge derives Safe authority from the private VM
connection, not an ID or path chosen by the agent. Child-Safe creation records
provenance, allocates a distinct volume and obeys family/quota limits. Automatic
startup can delegate only the requested client's supported credential and admit
the saved task with its stable request ID. Missing or unsupported credentials
leave an explicit authentication requirement. Installed-VM and real-provider
qualification remain open; see [provider limits](../../docs/PROVIDERS.md).

## Networking and files

Each online Safe owns a gateway using Tor or an explicitly configured SOCKS5
proxy. Open Internet, Strict and Offline apply to all processes in that Safe.
There is no direct fallback, local destination DNS or UDP bypass. Transitions
revoke existing routes and verify the selected transport before reopening them.
The Debian host's physical connectivity is a distinct network boundary.

File operations use fixed private guest ports, bounded metadata, positive root
selection, manifests and hash-checked payloads. Desktop import/export streams
never mount or share a host folder. Removable filesystems are parsed in
separate media VMs. Personal disk backups can contain native provider
credentials; they must not be described as credential-free Share packages.

Share uses a separate offline maintenance profile and the
[portable container](../oblivion-share/README.md). Export supports one closed
Safe, a branch or all Safes through a fixed, leased source set. Import stages new
offline volumes and atomically publishes the collection after full container
verification. Inspect/discard are explicit recovery operations; committed
collections cannot be discarded. See [Share](../../docs/SHARING.md).
Two-installation acceptance remains open. OnionShare owns separate
transfer VM lifetimes; public large-backup qualification remains open.

## Trusted interfaces

`oblivion-storage --config /etc/oblivion/controller.json` is an internal root
interface. Its root-owned configuration fixes paths, resources and allowed
roles. `/run/oblivion-control.sock` authenticates the configured manager UID
with `SO_PEERCRED`; clients verify the controller's root identity. Operation
frames are bounded and unknown fields rejected. Passwords use private channels,
not argv, environment values or temporary key files.

Desktop and Live launchers select their native VM backend; an external Linux
installation does not run the privileged controller on the user's operating
system. A runtime failure cannot silently fall back to a local controller.
The Linux vsock relay also requires a fresh private per-boot credential because
host CID alone is not a user identity.

Only specific data sockets are delegated to clients. QMP, arbitrary host paths
and root descriptors are not. QEMU roles have separate identities and confined
systemd units. The terminal boundary filters guest controls that could affect
the outer terminal; noninteractive stdout remains byte-preserving.

## Checks

From this package:

```sh
cargo check --locked --lib --bins
cargo test --locked --lib --bin oblivion
```

Linux controller and protocol suites run in CI with synthetic fixtures. An
explicit `lab-emulation` feature exists for diagnostic software-emulation
fixtures; production requires hardware virtualization and never falls back to
TCG automatically. The Mac diagnostic build has booted nested Safes and passed
recorded storage and file-transfer exercises. Native-terminal qualification and
the final distribution profile remain open, alongside Linux hardware, Windows
and physical Live-media acceptance. See the [acceptance register](../../docs/ACCEPTANCE.md).
