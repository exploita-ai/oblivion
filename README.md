<p align="center">
  <img src="assets/oblivion-logo.svg" width="900" alt="Oblivion">
</p>

<h1 align="center">A privacy layer for your coding agents</h1>

<p align="center">
  Keep your agent. Keep your terminal.<br>
  Run Codex, Claude Code and OpenCode 2 inside isolated, encrypted <strong>Safes</strong>.
</p>

<p align="center">
  <a href="https://github.com/exploita-ai/oblivion/actions/workflows/oblivion-check.yml"><img alt="Source checks" src="https://github.com/exploita-ai/oblivion/actions/workflows/oblivion-check.yml/badge.svg?branch=dev"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/Oblivion-MIT-d32f2f.svg"></a>
  <a href="docs/oblivion1.0-roadmap.md"><img alt="Status: 1.0 in development" src="https://img.shields.io/badge/status-1.0%20in%20development-d32f2f.svg"></a>
  <a href="https://github.com/exploita-ai/oblivion/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/exploita-ai/oblivion?color=d32f2f"></a>
</p>

```sh
# Create a new Safe and run the official client inside it
oblivion run --name research codex

# Use the same encrypted workspace with another agent
oblivion run --safe research claude

# Pass native agent arguments unchanged
oblivion run --safe research codex resume YOUR_NATIVE_SESSION_ID
oblivion run --safe research opencode2 --help

# Or open Oblivion's terminal manager
oblivion
```

**Oblivion 1.0 is in development. These examples describe the current source,
not a released desktop installer.** Native VM qualification and the complete
cross-agent persistence workflow are unfinished. Published
[0.x releases](https://github.com/exploita-ai/oblivion/releases) contain the
previous Live-only product and its modified OpenCode client. They do not contain
this launcher. The [roadmap](docs/oblivion1.0-roadmap.md) records implementation
progress, open issues and release acceptance gates.

On a prepared installation, the first new-Safe launch guides you through
encrypted-storage setup and unlock. `--ephemeral` starts in RAM without opening
the persistent archive. An existing `--safe` request never creates a replacement
when its archive or name is missing.

## What is a Safe?

A Safe is a separate Linux VM with its own encrypted disk, home, workspace,
agent profiles and network gateway. Several agent sessions can use the same
Safe and its files. Different Safes have separate filesystems and credential
stores. Scoped provider-credential delegation to an agent-created child is a
planned exception; it does not share a filesystem or copy a whole agent profile.
Closing a Safe stops its processes and locks its volume; it does not delete its
persistent conversations or files.

On desktop systems, a native headless launcher manages a Debian controller VM
and connects your existing terminal to the Safe. No UTM or VirtualBox window is
part of this flow. On **Oblivion Live**, the Debian host runs that same controller
directly. Debian owns hardware drivers, Wi-Fi, keyboard and operating-system
preferences; Oblivion owns Safes and its application settings.

```text
Your terminal                         Oblivion Live
     │                                     │
Native launcher                            │
     │                                     │
Headless Debian controller VM       Direct Debian controller
     └──────────────────┬──────────────────┘
                        ├─ Safe A: VM + encrypted disk + gateway
                        └─ Safe B: VM + encrypted disk + gateway
```

## Built into the stack

| Capability | Boundary |
| --- | --- |
| **Official clients** | Unmodified, pinned Codex, Claude Code and OpenCode 2 executables. Agent arguments stay separate; no shell command reconstruction. |
| **Encrypted storage** | A general LUKS2 archive for Oblivion's catalog and settings, with an independent LUKS2 volume for each persistent Safe. |
| **Ephemeral mode** | Application state and new Safes in RAM, without unlocking or borrowing credentials from the persistent archive. |
| **Per-Safe networking** | Tor or an explicitly configured SOCKS5 proxy; Open Internet, Strict and Offline policies. No direct fallback. |
| **Explicit file copies** | Local selection, guest browser, reviewed manifests and verified hashes through private streams. No shared host folders. |
| **Inactivity locking** | Human input renews the timer; generated output and background tasks do not. Locking stops active work. |
| **Agent tools** | Scoped MCP operations for Safe status, child-Safe creation, managed chat jobs and Tor rotation. |
| **Portable history** | A canonical catalog and adapters for the three native resume stores. Provider-specific records have explicit portability limits. |
| **Share** | Export one Safe, a family branch or all Safes to a separate passphrase-encrypted package. Import into new offline volumes after full verification. |
| **Personal backup** | [Copy the complete closed encrypted volume](docs/BACKUPS.md) through a revocable private stream. Restore the original identity using its original password; native credentials may be included. |
| **Family passwords** | [Review and change one local family's password](docs/PASSWORDS.md), with explicit recovery after interruption. Existing backup passwords and data keys are unchanged. |

These are source capabilities with different levels of verification. Component
checks do not establish that the complete installed product is ready for
sensitive use. See the roadmap for the exact remaining VM and hardware gates.

Agent-created Safes are marked in the manager. Their inspector separates parent,
requested client, storage and creation record from the actual VM and managed-job
state. Creation can delegate the requested client's supported credential and
start the saved task in the child's own VM. Missing or unsupported login leaves
an explicit authentication requirement. The inspector also supports offline
review and manual start or recovery of a saved task.
An uncertain submission is reconciled with the same request; a new attempt
requires a confirmed failure or cancellation and an explicit retry. Back leaves
the job active; inactivity locking still stops work. Startup observations are
separate from actual guest job outcomes. Native login remains a fallback where
credential-only delegation is unavailable. This path still needs installed-VM
and real-provider qualification. See [provider limits](docs/PROVIDERS.md).

## Networking

Tor is the default transport. You can select a SOCKS5 proxy when opening a Safe:

```sh
oblivion run --safe research --tor codex
oblivion run --safe research -x socks5h://192.0.2.10:1080 claude
oblivion run --safe research --proxy-profile office opencode2

# Change the selected Safe from another terminal
oblivion network set --safe research --policy offline
oblivion network set --safe research --tor
```

The address above is a documentation example. Named proxy profiles keep their
credentials inside encrypted application storage. A proxy URL containing a
password can remain in your terminal's command history; entering it through the
private prompt avoids putting it in argv.

All processes in a Safe, including shells, package managers and programs run
with sudo, pass through its gateway. DNS for requested destinations is resolved
through the selected transport. UDP is blocked; Tor and this SOCKS5 integration
provide TCP connectivity. Open Internet permits public TCP destinations while
retaining explicit blocks and address restrictions. Strict requires allow
rules. Offline denies provider and tool traffic.

Changing transport or rotating Tor interrupts the selected Safe's existing
connections. The application route stays blocked until verification succeeds;
an unconfirmed failure stays blocked. Other Safes have independent gateways.
Dedicated telemetry collectors known for the pinned clients are blocked, and
supported client telemetry settings are disabled. This cannot distinguish
telemetry from model traffic sharing the same encrypted destination.

The footer separates the host's `Network` link from verified `Tor` and `SOCKS5`
routes. A Safe's current `Strict`, `Open Internet` or `Offline` policy appears
beside Network only with a fresh observation for that exact host and Safe
opening. A lock, reopening or expired observation removes the old policy and
protected-route marks. The physical Network indicator remains available on the
welcome screen; it does not assert that a provider is reachable.

## Files and authentication

Authenticate through each official agent inside the Safe. Oblivion does not
replace provider login flows or reuse the desktop's agent profile. Provider
accounts, permissions and billing remain yours. The clients' own licenses and
service terms still apply.

```sh
oblivion safe open research
oblivion files import --safe research ./project --name project
oblivion files list --safe research workspace/project --json
oblivion files export --safe research workspace/project ./exports
oblivion close research
```

Imported files enter the Safe only through an explicit copy. Export destinations
must already exist. Files shared by agents in one Safe remain shared by those
agents; they can read and modify them according to guest permissions.

In the manager, open **Files → Import**, then press **P** for **Enter path**.
Paste a local path or `file://` URL, inspect it and choose it before confirming
the copy. Terminals that paste a path on drop can use the same field. This is
an explicit local selection, with no shared folder or virtual exchange disk.
Literal paths and a single surrounding quote pair are accepted; shell escapes
and environment-variable expansion are not interpreted.

Share differs from a personal backup: a full disk backup can contain saved
provider credentials. Share selects portable conversations and files, excluding
agent profiles, credential stores and the installed OS overlay. Possible secrets
inside selected document contents or messages require review; automatic scanning
is best effort.

```sh
oblivion share export --safe research research.oblivion-share
oblivion share export --branch research team.oblivion-share
oblivion share export --all collection.oblivion-share

# On the receiving installation
oblivion share import research.oblivion-share
```

The sender closes the selected Safes, reviews the content and chooses a separate
sharing passphrase. The receiver chooses a new password for the imported Safes.
Existing Safes remain intact; imported Safes get new identities and keys and
start offline. Importing application lock settings requires `--apply-settings`.
See [Share and recovery](docs/SHARING.md) for selection and interrupted imports.
These paths are implemented in source; acceptance between two installed
Oblivion instances remains a release gate.

## Privacy model

Oblivion protects storage boundaries and controls a Safe's network path. It is
**not an anonymity guarantee**, and cloud API mode is **not air-gapped**.

- A remote model provider receives the context sent by its client. Tor does not
  conceal your provider account or API key from that provider.
- Encryption protects closed volumes. While work runs, plaintext and unlocked
  keys exist in memory, and authorized processes can read their data.
- On desktop systems, the outer OS and hypervisor can observe terminal content,
  input and VM memory. Oblivion cannot neutralize a compromised host or control
  its swap, crash captures, terminal history and backups.
- The managed guest uses RAM-backed temporary paths and disables swap and core
  dumps. Persistent Safe writes stay inside its encrypted volume.
- A closed Safe's disk is not mounted by the controller or desktop. Cleanup
  failures remain visible as recovery states rather than successful locks.

Oblivion has not received an independent security audit. Avoid irreplaceable
secrets while the implementation and its release gates remain experimental.
Local inference is deferred until after 1.0.

## Platform status

| Environment | Current source status |
| --- | --- |
| **Debian Live, amd64 / arm64** | Image build path retained for the shared stack; new 1.0 images still need end-to-end qualification. |
| **Debian controller package, amd64 / arm64** | Development `.deb` source and package lifecycle fixtures implemented for the trusted controller layer. Real-role and hardware acceptance remain open. |
| **Linux desktop, x86_64** | Native headless QEMU/KVM helper implemented; actual hardware acceptance remains open. |
| **macOS, Apple Silicon** | Native Virtualization.framework helper implemented. Inner Safe KVM boots currently fail in qualification on the test Mac; not a supported release yet. |
| **Windows** | Planned; no qualified native backend or installer yet. |

Hardware virtualization is required. There is no automatic software-emulation
fallback. Emulator-only development tests do not qualify a platform.

## Build and contribute

Use the Bun version pinned in [package.json](package.json):

```sh
bun install --frozen-lockfile
bun run check

# Build a current-source development image; Docker is required
OBLIVION_ARCH=amd64 bun run build:iso
OBLIVION_ARCH=arm64 bun run build:iso

# Build the development package for the trusted Debian controller layer
OBLIVION_ARCH=amd64 OBLIVION_DEB_VERSION=1.0.0~dev20261104 bun run build:deb
```

The ISO and inventories are written under `artifacts/oblivion-stack-ARCH/`.
Verify `SHA256SUMS` there. Checksums detect damaged files; they are not signed
release provenance. CI builds draft prereleases and does not automatically
publish an image as a qualified release.

The [Debian package guide](docs/DEBIAN.md) covers dependencies, installation and
data-preserving removal for a dedicated controller or Debian runtime VM.
Native desktop packaging also needs the platform launcher and headless helper.

Contributions should target `dev`, use synthetic fixtures and document the trust
boundary affected by a change. See [CONTRIBUTING.md](CONTRIBUTING.md), the
[1.0 roadmap](docs/oblivion1.0-roadmap.md), and the component READMEs under
`packages/oblivion-*`. Good first contributions include reproducible platform
reports, terminal interaction bugs and tests of interrupted cleanup.

Oblivion's source is MIT licensed. Retained OpenCode UI utilities, Termcn-derived
components, terminal/clipboard components and other third-party code retain
their notices. Official agent binaries and Debian packages retain their own
licenses and terms. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
