# Oblivion host controller

The trusted Linux controller used by Oblivion's Debian live image, whether
Debian boots directly or runs as the outer VM. It manages LUKS2 storage,
credentials and isolated guest lifetimes. OpenCode and user tools execute in
the session guest; cryptography is delegated to cryptsetup/LUKS2.

The current source includes protected and ephemeral sessions, offline
Documents and Terminal, remote chat startup, media transfers, conversation
exports, encrypted backup/restore, redacted diagnostics and OnionShare
orchestration. Source implementation, laboratory tests and supported-image
acceptance have separate status in [STATUS.md](../../docs/STATUS.md).
These operations are packaged in the experimental `v0.1.0-beta.2` images.
See [downloads and release limits](../../README.md#download-oblivion);
packaging does not close the remaining supported-image acceptance gates.

## Storage and session lifetime

- A general LUKS2 vault holds settings, saved provider keys and independent
  session LUKS2 files. Creation uses Argon2id and allocates space up front.
- Creation stages unpublished containers in `.pending` files. Only formatted,
  closed containers are published, using no-replace rename and file/directory
  synchronization. Discarding an incomplete attempt requires confirmation.
- The privileged controller mounts the general filesystem privately with
  `nodev,nosuid,noexec`. It formats session filesystems but never mounts them.
- One session volume and one session VM may be open at a time. Each guest gets
  a read-only system image and its own writable session block device; there
  is no shared host/session folder or filesystem shared between sessions.
- The guest mounts its session at `/vault`. Its non-root agent and terminal
  share that session's workspace and imports. Multiple chats use the same
  encrypted database and filesystem.
- Ephemeral sessions use RAM-backed state. Loading an existing host profile
  read-only disables ext4 journal replay; the ephemeral path does not silently
  turn saved session volumes into writable storage.
- Offline Documents and Terminal require no provider key, model process or
  network device. Starting chat stops the offline VM and starts the chat VM
  on the same unlocked volume, without asking for its password again.
- Close and lock revoke access, stop auxiliary operations, verify guest
  termination, then use ordinary unmount and cryptsetup removal. Busy resources
  cause a recovery error; there is no lazy unmount or deferred mapping removal.

Kernel mappings and mount state are authoritative. A root-owned recovery latch
in RAM prevents new opens after unconfirmed cleanup, including across service
restarts. A lost Tor checkpoint is distinguished from a failure to terminate a
VM; unrelated safe cleanup still runs. Failed chat startup revokes its grant
and returns to offline access after verified cleanup.

Chat, Documents and Terminal are views into the active guest. Switching views
keeps that guest running; closing it ends all its processes. The manager uses
`F6`, `F7`, `F8` and `Ctrl+Q`. `/new` and `/resume` operate on chats within the
selected protected session; `/exit`, `/quit` and `/q` request session closure.

## Credentials and network

The general encrypted profile stores multiple named provider keys, a global
default, network preferences, keyboard/variant and time zone. A key override
lasts for one session opening. Ephemeral configuration stays in RAM.

The session receives a revocable capability for the selected gateway, rather
than the provider's API key. The model gateway uses Tor by default or an
explicit SOCKS5 proxy. Session TCP and destination-name resolution go through
that boundary; direct DNS, UDP/QUIC and IPv6 bypasses are denied. There is no
automatic direct fallback. The live host separately permits necessary local
network setup such as DHCP and Wi-Fi authentication.

Network indicators use fresh controller observations. Configuring Tor alone
is insufficient to report readiness. The OnionShare transfer path has its own
Tor state and observation lifecycle, independent of the model route.
See [ARCHITECTURE.md](../../docs/ARCHITECTURE.md) for the complete policy.

## Files, exports and backups

External filesystems are parsed in separate networkless media VMs. The host
selects an eligible device and grants read-only import or explicitly approved
export authority. The session sees selected file bytes through private copy
ports, never the external block device. The manager receives bounded listings,
manifests, progress and receipts, rather than document payloads.

Documents exposes only `workspace` and `imports`. Imports verify hashes and
publish a new directory after approval. Exports create a fresh destination
and require unmount/flush acknowledgement and cleanup before success. Recovery
records stay inside the session; uncertain or published copies are not silently
deleted or retried. Supported readers/writers include ext4, FAT and exFAT.
Prepared virtual media use explicit eligibility rules, without shared folders.

Conversation export creates Markdown or OpenCode JSON under
`workspace/chat-exports`; in-progress responses are omitted. Export that file
through Documents to move it outside the encrypted session. Redacted diagnostic
export has a separate allowlisted schema and review flow.

An encrypted session backup is a closed LUKS2 volume named `session.oblivion`.
It preserves all chats, shared documents and embedded session metadata. Restore
creates an independent session with a fresh host identifier; the original
session password is required. General settings and provider keys are excluded.
The controller supplies only a pinned ciphertext descriptor to the isolated
copy endpoint. Originals are preserved on refusal, corruption or cancellation.

OnionShare adds separate Tor and file-transfer guests. Received files remain
in private intake until review and explicit import approval. Sharing stages
only selected documents, or delegates a single closed read-only ciphertext
volume for encrypted backup sharing. Cancellation, expiry and lost ownership
revoke publication and reap these actors before storage closure. Public
large-backup qualification remains open. See the
[OnionShare adapter](../oblivion-onion/README.md) and
[copy engine](../oblivion-transfer/README.md).

## Trusted interfaces

`oblivion-storage --config /etc/oblivion/controller.json <operation>` is an
internal root interface. The root-owned, mode-0600 configuration fixes image
paths, guest resources and enabled roles; it does not accept arbitrary client
commands. [controller.example.json](controller.example.json) is a development
example; live images use [live-controller.json](../../script/oblivion/live-controller.json).
Do not install these fixed system accounts and service profiles on an ordinary
multiuser workstation.

The non-root OpenTUI manager uses `/run/oblivion-control.sock`, mode 0600.
The daemon authenticates its configured manager UID with `SO_PEERCRED`;
clients verify a root-owned peer. Requests are framed, bounded and allowlisted,
with operation-specific payload limits and rejection of unknown fields. Passwords
use private stdin/socket channels, never command arguments, environment values
or temporary key files. Protocol definitions live in [ipc.rs](src/ipc.rs) and
[control.rs](src/control.rs), rather than a separate public OpenCode API.

The console and terminal operations delegate only the selected data socket
using `SCM_RIGHTS`. QMP and arbitrary filesystem paths are never delegated to
the manager. QEMU roles have dedicated identities and confined systemd units;
the manager filters guest terminal controls before rendering them.

Runtime directories and system temporary paths use RAM. Swap, hibernation,
core dumps and persistent/forwarded journals are disabled in the image profile.
Owned secret buffers are cleared, without promising immediate erasure of every
kernel or managed-runtime memory copy. An outer OS or hypervisor remains trusted
for input, display, RAM, swap and snapshots.

## Build and verification

The production backend requires Linux and usable KVM. On macOS it runs inside
Debian through a qualified outer-VM profile. The explicit `lab-emulation` Cargo
feature permits synthetic TCG tests; production has no software-emulation fallback.

From this package on Linux:

```sh
cargo test --locked
cargo check --locked --all-targets
cargo build --locked --release
```

The [development guide](../../docs/DEVELOPMENT.md) documents disposable Debian
laboratories with actual cryptsetup, device-mapper, systemd, guest binaries and
copy endpoints. Some tests use nested TCG and synthetic data; those results do
not establish supported KVM hardware, power-loss or real-device acceptance.

Remaining release gates include full operational-candidate UTM/KVM/physical
media testing, fault and upgrade/recovery coverage, public large-backup Tor
transfers, measured resource costs, signed provenance and independent review.
