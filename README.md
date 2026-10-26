<p align="center">
  <img src="assets/oblivion-logo.svg" width="900" alt="Oblivion — private by design">
</p>

<h1 align="center">A hardened live environment for high-privacy LLM coding</h1>

<p align="center">
  Boot from USB. Unlock an isolated workspace. Run a full coding agent.<br>
  Shut down and leave the live runtime behind.
</p>

<p align="center">
  <a href="https://github.com/exploita-ai/oblivion/actions/workflows/oblivion-check.yml"><img alt="CI" src="https://github.com/exploita-ai/oblivion/actions/workflows/oblivion-check.yml/badge.svg?branch=dev"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-d32f2f.svg"></a>
  <a href="#project-status"><img alt="Status: pre-beta" src="https://img.shields.io/badge/status-pre--beta-d32f2f.svg"></a>
  <img alt="Platforms: amd64 and arm64" src="https://img.shields.io/badge/arch-amd64%20%7C%20arm64-27272a.svg">
  <a href="https://github.com/exploita-ai/oblivion/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/exploita-ai/oblivion?style=flat&color=d32f2f"></a>
</p>

<p align="center">
  <a href="#why-oblivion">Why Oblivion</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#privacy-model">Privacy model</a> ·
  <a href="#build-from-source">Build</a> ·
  <a href="#join-the-project">Contribute</a>
</p>

---

Oblivion is a minimal Debian live system built around an [OpenCode](https://github.com/anomalyco/opencode)-derived coding agent. It gives every persistent session its own VM and LUKS2-encrypted volume, keeps the live runtime in memory, and routes session traffic through a dedicated Tor or SOCKS5 gateway with no direct fallback.

It is not another chat wrapper. The agent keeps its coding tools and works with the documents you explicitly place inside its isolated session.

> [!WARNING]
> Oblivion is pre-beta research software. It has not received an independent security audit. The current images are development candidates, not a promise of anonymity or a safe place for irreplaceable secrets.

## Why Oblivion

Ordinary coding agents can leave conversations, logs, temporary files, credentials, and working copies across the host filesystem. Oblivion changes the boundary: the host OS is not running, the live system is disposable, and a protected session owns a separate encrypted workspace.

The goal is not to turn an online model into an air-gapped model. The current cloud mode still sends the context you approve to the configured provider. A future local inference engine is planned for genuinely offline operation.

| | Boundary | What Oblivion does |
| --- | --- | --- |
| **At rest** | USB storage | Separate LUKS2 volume and password for every persistent session |
| **While running** | Live host | Read-only Debian base with runtime and temporary paths in RAM |
| **Between sessions** | Workspaces | One open volume and one session VM at a time; no shared session filesystem |
| **On the network** | Model traffic | Dedicated gateway VM with Tor or explicit SOCKS5 and no direct fallback |
| **For documents** | Offline work | Files can be opened without a network device, API key, or agent process |

## Architecture

```text
USB boot
└── minimal read-only Debian live system
    ├── tmpfs runtime (discarded on shutdown)
    ├── general LUKS2 vault
    │   └── Wi-Fi, API keys and host preferences
    ├── Oblivion manager
    ├── isolated gateway VM
    │   └── Tor or an explicit SOCKS5 proxy; no direct fallback
    └── one active protected session
        ├── independent LUKS2 volume
        └── session VM
            ├── OpenCode-derived coding agent
            ├── shared workspace and imports for that session
            └── multiple chats inside the same encrypted session
```

Documents mode starts the session VM without a network device, provider token, or agent process. Starting a chat reuses the unlocked session volume and replaces the offline VM with the networked chat VM. The host receives control messages and file metadata; it does not mount a session filesystem.

## Privacy model

- A general encrypted vault stores host settings and API keys.
- Every persistent session has a different LUKS2 volume and password.
- Only one session volume and one session VM may be open at a time.
- Ephemeral mode keeps its working state in RAM and does not intentionally modify the USB vault.
- Runtime paths and temporary files live on tmpfs in the live system.
- Documents can be opened without starting the gateway or supplying an API key.
- Session egress is mediated by a dedicated gateway VM using Tor or a configured SOCKS5 proxy.
- Direct session access is deny-by-default; Oblivion does not fall back to the host connection.
- API keys are injected for an opening and removed from the session runtime when it closes.
- The production profile disables OpenCode logging, telemetry, update checks, provider discovery, crash dumps, and project-level configuration loading.

These are implementation goals backed by automated and VM-level tests. They are not a formal proof.

## What Oblivion cannot protect

- Prompts, selected documents, tool results, and model output are visible to the cloud provider you use.
- Data is plaintext in RAM while a vault or session is unlocked.
- A compromised BIOS, firmware, kernel, hypervisor, keyboard, display, or physical machine can observe an active session.
- Tor can hide the source network from a provider, but it cannot make submitted content private from that provider.
- Exported files are protected only by the destination you choose.
- Development images expose diagnostics that are deliberately absent from release images.

Read [SECURITY.md](SECURITY.md) before testing Oblivion with sensitive data.

## Project status

| Area | Status |
| --- | --- |
| amd64 live USB boot | Tested on physical hardware |
| arm64 live image | Built; physical and generic-hypervisor validation continues |
| General and per-session LUKS2 persistence | Implemented and tested |
| Offline Documents VM | Implemented |
| Tor and SOCKS5 gateway | Implemented; hardening and UX work continue |
| Multiple chats per encrypted session | Implemented; persistence recovery under test |
| Import/export | Implemented with manifest and recovery checks |
| Reproducible signed releases | Not yet available |
| Independent security audit | Not yet performed |
| Local inference | Planned |

The maintained architecture, development guide and release status live in
[`docs`](docs). Per-commit test evidence is published by CI instead of being
committed as historical snapshots.

## Build from source

Development currently requires macOS or Linux, [Bun 1.4.4](https://bun.sh), Docker with Buildx, Python 3, and enough disk space for Debian and VM images.

```sh
git clone https://github.com/exploita-ai/oblivion.git
cd oblivion
bun install --frozen-lockfile

# Canonical lint and type check
bun run check

# Intel and AMD 64-bit PCs (`amd64` / `x86_64`)
bun run build:iso

# Apple Silicon and other 64-bit ARM systems (`arm64` / `aarch64`)
OBLIVION_ARCH=arm64 bun run build:iso
```

Intel and AMD use the same `amd64` image; 32-bit x86 is not supported. To run
Oblivion from QEMU or VirtualBox without a physical USB, prepare a writable
virtual USB and follow the nested-virtualization requirements in the
[development guide](docs/DEVELOPMENT.md#run-from-a-virtual-machine).

On Apple Silicon, the native VM path is the `arm64` image in UTM using the Apple
Virtualization backend. Full sessions require macOS 15 and an M3 or newer chip;
M1/M2 and VirtualBox ARM cannot expose the nested virtualization Oblivion needs.

Build output is written under `artifacts/`, which is intentionally ignored by Git. The hardware helper creates a dedicated SSH key outside the repository for development images:

```sh
bun run build:hardware
```

Do not distribute a development image as a release image.

## Repository map

- `packages/oblivion-host` — trusted storage, VM lifecycle, manager bridge, console, display, and transfers.
- `packages/oblivion-gateway` — isolated egress broker, policy enforcement, Tor/SOCKS5 supervision, and firewall control.
- `packages/oblivion-manager` — the full-screen host TUI.
- `packages/oblivion-transfer` — bounded import/export protocol and filesystem operations.
- `packages/oblivion-transport` and `packages/oblivion-tor-state` — shared transport contracts.
- `packages/cli`, `packages/tui`, `packages/core`, and related `@opencode/*` packages — the retained OpenCode coding-agent runtime.
- `script/oblivion` — image construction, VM labs, hardware helpers, and security regression tests.
- `docs` — maintained architecture, development, security and release-status documentation.

The repository intentionally excludes OpenCode's web app, desktop app, hosted console, website, telemetry services, deployment infrastructure, and translated upstream marketing documentation.

## Development

Use the package-local test commands described in [CONTRIBUTING.md](CONTRIBUTING.md). The canonical repository check is:

```sh
bun run check
```

For the agent TUI against an already running local OpenCode service:

```sh
bun run dev:live /path/to/project
```

Never commit API keys, session volumes, captured traffic, generated images, or user documents. Synthetic laboratory credentials are clearly marked and must not be accepted by production images.

## OpenCode attribution

Oblivion is an independent project derived from OpenCode v2 and is not affiliated with or endorsed by the OpenCode team. The retained agent code remains under its MIT license. See [NOTICE](NOTICE) and [LICENSE](LICENSE).

## Join the project

Oblivion is being built in public. Contributions are welcome across the TUI, Debian image, isolation boundary, network gateway, reproducible builds, hardware support, documentation, and security testing.

- Read the [contribution guide](CONTRIBUTING.md) before opening a pull request.
- Explore the [architecture](docs/ARCHITECTURE.md) and current [project status](docs/STATUS.md).
- Open an issue for bugs, hardware reports, UX feedback, or focused proposals.
- Report vulnerabilities privately through GitHub Security Advisories as described in [SECURITY.md](SECURITY.md).

If the mission resonates with you, star the repository and help us test Oblivion on real hardware.

## License

MIT. Copyright notices for upstream OpenCode and Oblivion contributors are preserved in [LICENSE](LICENSE).
