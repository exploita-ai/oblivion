# Repository map

Oblivion 1.0 has two distributions: a native terminal launcher for desktop
systems and a bootable Debian Live system. Both start the same private Debian
controller VM, which owns the Safe VMs and their gateways. The Live ISO and the
controller ISO have different roles; neither is a retired artifact format.

This page maps source ownership. The [roadmap](oblivion1.0-roadmap.md) and
[acceptance matrix](ACCEPTANCE.md) track implementation and qualification.
Presence in this map does not mean a platform or feature has passed acceptance.

## Current packages

All package paths below are relative to `packages/`. These are current source
components, including retained backend integrations and platform work awaiting
qualification.

| Package | Role | Used by |
| --- | --- | --- |
| `oblivion-cli` | Shared command grammar, terminal handoff, Files, Share and backup frontend; Windows command entrypoint | Desktop and Live |
| `oblivion-host` | Unix launcher, Linux controller, encrypted storage, Safe lifecycle and guest/role assets; Live display entrypoint | Desktop and Live |
| `oblivion-manager` | Bun/Solid/OpenTUI manager and local preview fixtures | Desktop and Live |
| `oblivion-native` | Swift Apple Virtualization helper | macOS desktop |
| `oblivion-native-linux` | QEMU/KVM helper and Live media sidecar | Linux desktop and Live |
| `oblivion-native-windows` | HCS/Hyper-V helper, broker, installation and private Windows I/O | Windows desktop, experimental |
| `oblivion-wire` | Shared private protocol types and framing | Desktop, controller and guests |
| `oblivion-bundle` | Desktop manifest and inventory validation | Desktop and the launcher bundled in Live |
| `oblivion-gateway` | Tor/SOCKS5 routing, network policy, rotation and service gateways | Shared controller/guest stack |
| `oblivion-transport` | Transport profiles, proxy configuration and policy types | Shared launcher/controller stack |
| `oblivion-tor-state` | Persistent Tor-state formats and validation | Shared controller/gateway stack |
| `oblivion-transfer` | Verified copy streams, local endpoints, media recovery and Onion file supervisor | Desktop, controller and guests |
| `oblivion-share` | Encrypted portable Share container and control protocol | Desktop and Live |
| `oblivion-history` | Python adapters for portable native-agent histories in Share | Safe guest; no shared-history server |
| `oblivion-tools` | Scoped MCP tools for the official agents | Safe guest |
| `oblivion-onion` | OnionShare adapter, file-VM services and component laboratories | Integrated controller/backend and image packaging; 1.0 user interface still missing |
| `oblivion-clipboard` | Wayland clipboard integration for the outer graphical terminal | Live display |
| `theme` | Semantic terminal theme, including retained upstream utilities | Manager |
| `tui-kit` | Shared terminal UI components and selection behavior | Manager |

The official Codex, Claude Code and OpenCode 2 executables are installed from
the pinned [agent inventory](../script/oblivion/install-agents.json). Their
application source is not maintained in this repository.

## Images, installers and laboratories

The [script index](../script/oblivion/README.md) describes the builders and
manual inspection tools. The important boundaries are:

| Source or command | Purpose |
| --- | --- |
| `bun run build:runtime` | Build the private controller ISO shared by desktop and Live |
| `bun run build:live` | Build the outer bootable Live OS with its matching controller embedded |
| `script/oblivion/build-image.sh` | One implementation of those two image builds, with an explicit `controller` or `live` role |
| `script/oblivion/build-native.sh`, `build-native-windows.ps1`, `build-desktop-deb.sh` | Assemble platform desktop bundles/packages |
| `bun run build:deb`, `script/oblivion/debian/` | Development package for the trusted Debian controller; distinct from the desktop package |
| `script/oblivion/controller-*`, `pack-vm-assets.sh`, `vm-common-setup.sh` | Shared controller and inner VM composition |
| `script/oblivion/live-*`, `live-os/`, `display/` | Outer Live boot, physical media, OS controls and terminal display |
| `script/oblivion/Dockerfile.vm-lab` | Shared build graph with production and diagnostic targets; its filename does not make it disposable |
| `script/oblivion/run-*-lab.py`, `test-*`, package tests | Component and integration verification; not installed product entrypoints |

Production image paths do not gain diagnostic access merely because they share
a Dockerfile with lab targets. Inspect the selected target and its inputs when
changing image composition.

## Retired source and historical records

The modified OpenCode application has already been removed from the 1.0 source
tree. The former `packages/core`, `client`, `protocol`, `schema`, `server`, `tui`
and other fork packages are not dependencies to restore. Their old
`opencode service`, `dev:live`, shared-history watcher and client-generation
instructions do not describe current development.

The orphan `packet_capture.py` and `onion_recipient.py` helper modules have also
been removed: their only importing beta harnesses were retired with the agent
fork. The standalone `vm-onion-recipient.py` laboratory remains available.
The relay's optional progress-notification protocol was removed with the old
manager consumer; current Files progress uses its own native event stream.
The unused `oblivion-host/examples/ipc-probe.rs` was removed with its build
inventory entries because its commands and payload expectations predated the
current control protocol.

The development guides under `.opencode/skills/` now target the current
packages. The directory name remains the repository's skill-discovery location.
`theme` and `tui-kit` intentionally retain upstream code and notices; see
[NOTICE](../NOTICE).

Keep these records distinct from runtime instructions:

| Record | Status |
| --- | --- |
| [CHANGELOG.md](../CHANGELOG.md) | Published 0.x release history |
| [STATUS.md](STATUS.md) | Dated technical evidence, including superseded experiments |
| [ACCEPTANCE.md](ACCEPTANCE.md) | Scenarios and revision-specific test outcomes; a previous failure or success must be read with its later follow-ups |

Do not delete a component solely because its name contains `Live`, `history`,
`onion`, `opencode` or `legacy`. For example, Codex native-format values and
Wayland protocol names can legitimately contain `legacy`. This does not permit
backward-compatible Oblivion readers: internal payloads must satisfy the current
contract, and replaced implementations are removed. The retired shared-history
prototype document is available only in Git history.

The current contract requires explicit control slots, recovery flags, transfer
source metadata and network access policy. Relay failures use their own terminal
frame; the old empty-stderr marker is rejected. Tor state requires the pinned
version, and published transfers require their current transaction and receipt
records. The clipboard implements the protocol enabled by the pinned Live
compositor. Rebuild launcher, controller and guest components together when
these internal contracts change; old candidates are not compatible test inputs.

## Local output and retention

These paths are ignored output, not source packages:

| Path | Handling |
| --- | --- |
| `node_modules/`, package `node_modules/` | Recreate from `bun.lock` with the pinned Bun version |
| `packages/*/target/` | Cargo build cache; recreate with the relevant package's locked dependencies |
| `.turbo/`, package `.turbo/`, `tsconfig.tsbuildinfo` | Check/build caches; a cache hit is not a fresh toolchain check |
| Package `dist/` | Generated build output, including the MCP bundle needed by image builds |
| `artifacts/oblivion-runtime-*` | Controller ISO and source/package/checksum evidence |
| `artifacts/oblivion-stack-*` | Outer Live ISO and evidence |
| `artifacts/oblivion-desktop-*`, `oblivion-desktop-deb-*`, `oblivion-debian-*` | Native bundles or Debian packages |
| `artifacts/oblivion-candidate/<revision>/` | Locally retained candidates and acceptance evidence; not the latest source by definition |
| `.opencode/references/` | Optional local reference checkout; not runtime input or a requirement of the current skills |

Keep evidence manifests and logs with the exact candidate they describe. Before
removing old candidates, check whether the acceptance register relies on their
evidence and whether the matching binaries are needed to reproduce an open
failure. Do not apply source-cache cleanup rules to provisioned Safe archives,
runtime backing disks or boot media.

## Remaining product work

The current release gates are the installed Mac flow, provider authentication
and native resume, network failure/privacy checks, child-Safe tasks and family
recovery, backup/Share between independent installations, and platform/resource
qualification. OnionShare still needs a current CLI/manager flow and its
corresponding acceptance checks. Maintain the detailed state in the
[roadmap](oblivion1.0-roadmap.md#9-lavoro-rimanente) instead of a second completion
checklist here. Branch promotion and release publication are separate from
source cleanup and passing component tests.
