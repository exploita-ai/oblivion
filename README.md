<p align="center">
  <img src="assets/oblivion-logo.svg" width="900" alt="Oblivion — private by design">
</p>

<h1 align="center">A private live environment for AI conversations, discovery and creation</h1>

<p align="center">
  Boot from USB. Talk, explore, work with documents, or use a full coding agent.<br>
  Lock the session and leave the live runtime behind.
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
  <a href="#tor-and-network-privacy">Tor</a> ·
  <a href="#remote-inference-providers">Providers</a> ·
  <a href="#where-oblivion-runs">Platforms</a> ·
  <a href="#build-from-source">Build</a> ·
  <a href="#join-the-project">Contribute</a>
</p>

---

Oblivion is a minimal Debian live system for private AI conversations, research,
document work and coding. It is built around an
[OpenCode](https://github.com/anomalyco/opencode)-derived agent, gives every
persistent session its own VM and LUKS2-encrypted volume, keeps the live runtime
in memory, and routes session traffic through a dedicated Tor or SOCKS5 gateway
with no direct fallback.

It is not only a coding tool and it is not another chat wrapper. A session can
hold several conversations and a shared document workspace: use it to think,
learn, investigate, write, build, or let the full agent operate on files you
explicitly place inside that isolated workspace.

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

## Tor and network privacy

Tor is the default remote-inference route. Oblivion runs it inside a dedicated
gateway VM rather than letting the session VM use the host connection. Provider
traffic and network access explicitly allowed for agent tools cross that gateway;
direct session egress has no fallback path. An explicit SOCKS5 proxy can replace
Tor when the user controls or trusts another route.

Tor provides **network anonymity, not content secrecy from the AI provider**.
It hides the user's public IP from the destination and prevents a single Tor
relay from seeing both ends of the circuit. HTTPS still protects the request
from the exit relay, but the selected provider must receive the prompt,
documents included as context, tool results and generated response in order to
perform inference. See the Tor Project's explanations of
[what Tor protects](https://support.torproject.org/about-tor/introduction/protections/)
and [Tor with HTTPS](https://support.torproject.org/about-tor/security/https-encryption-and-tor/).

Operational consequences are visible in the UI:

- `TOR READY` is shown only after bootstrap and isolation checks succeed.
- A configured proxy is not considered ready until SOCKS5 negotiation succeeds.
- Stale observations expire instead of leaving a reassuring green state behind.
- Oblivion does not contact a public “what is my IP” service automatically.
- Tor can be slower, can take time to bootstrap, and some providers or websites
  may block exit relays.

## Remote inference providers

Provider privacy is a separate boundary from Oblivion's local encryption. A
provider necessarily processes the content sent for a request. “Zero retention”
below describes each provider's published policy; it is not a technical property
that Oblivion can independently prove.

| Provider | Oblivion status | Published handling of inference content | Account and payment notes |
| --- | --- | --- | --- |
| [Abliteration.ai](https://abliteration.ai/) | **Integrated now** | Its [data-handling policy](https://abliteration.ai/data-handling) says core API prompts, completions and images are processed in memory, not stored and not used for training. Operational telemetry and billing metadata are retained. Optional web search/fetch is outside that zero-retention boundary. | Account and billing data are retained; its current privacy policy describes Stripe payment processing. |
| [Refuseless](https://refuseless.com/) | **Integrated now** | Its [privacy policy](https://refuseless.com/privacy) says prompts and outputs are not saved or used for training. It may route some requests to third-party model providers and explicitly says it cannot guarantee their retention policy in every case. | OpenAI-compatible API. Accepts card or BTC, ETH, USDT, USDC and XMR according to its [pricing page](https://refuseless.com/pricing). Signup uses email/password or Google; login and billing records are retained. A no-KYC guarantee is **not stated** in its public policy. |
| [OpenRouter](https://openrouter.ai/) | **Integrated with mandatory ZDR routing** | Oblivion overwrites every request with `zdr: true`, `data_collection: deny` and `allow_fallbacks: false`. OpenRouter [documents ZDR at endpoint level](https://openrouter.ai/docs/guides/features/zdr); a model with no eligible ZDR endpoint fails closed instead of falling back. | OpenRouter and the selected upstream still process the request. ZDR does not cover optional server tools or plugins; Oblivion does not enable those provider-side features. |

The production gateway allowlists exactly one endpoint for the provider selected
for that chat opening. The real API key remains in the gateway VM; the session
receives only a revocable local capability and the provider identifier. Refuseless
uses OpenCode's OpenAI-compatible adapter, while OpenRouter uses OpenCode's native
adapter. Provider routing fields supplied by a model or client cannot weaken the
gateway's OpenRouter ZDR policy. Oblivion will not silently route a request through
an unreviewed provider.

## What Oblivion cannot protect

- Prompts, selected documents, tool results, and model output are visible to the cloud provider you use.
- Data is plaintext in RAM while a vault or session is unlocked.
- A compromised BIOS, firmware, kernel, hypervisor, keyboard, display, or physical machine can observe an active session.
- Tor can hide the source network from a provider, but it cannot make submitted content private from that provider.
- Exported files are protected only by the destination you choose.
- Development images expose diagnostics that are deliberately absent from release images.

Read [SECURITY.md](SECURITY.md) before testing Oblivion with sensitive data.

## Where Oblivion runs

The physical live-USB path and the VM evaluation path have different security
properties. On a direct USB boot the computer's installed OS is not running. In
a VM, the outer OS and hypervisor can observe input, display, memory and storage.

| Host | CPU | Outer OS / hypervisor | Image | Current support |
| --- | --- | --- | --- | --- |
| PC booted directly from USB | Intel or AMD 64-bit (`x86_64`) with VT-x/AMD-V | Installed OS is not running | `amd64` | **Primary target; tested on physical hardware** |
| Linux workstation/server | `x86_64` with nested KVM | Linux + QEMU/KVM | `amd64` | Development/evaluation target |
| Linux ARM host | `aarch64` with nested KVM | Linux + QEMU/KVM | `arm64` | Supported design; hardware validation pending |
| Windows PC | Intel or AMD 64-bit with nested virtualization | Windows + VirtualBox | `amd64` | Supported design; physical validation pending |
| Apple Silicon Mac | M3 or newer | macOS 15+ + UTM Apple Virtualization | `arm64` | Native Mac evaluation target; nested KVM validated on M4 Pro |
| Apple Silicon Mac | M1 or M2 | macOS + UTM | `arm64` | Manager may boot; full sessions are unsupported because nested virtualization is unavailable |
| Intel Mac | Intel 64-bit | Hypervisor exposing nested VT-x | `amd64` | Unverified |
| 32-bit x86 or ARM, Windows on ARM without nested KVM | — | — | — | Unsupported |

Full sessions require nested hardware virtualization because Oblivion starts
separate gateway, session and transfer VMs. There is deliberately no slow
software-emulation fallback. See the detailed
[virtual-machine guide](docs/DEVELOPMENT.md#run-from-a-virtual-machine).

### Live USB requirements

- A 64-bit Intel/AMD PC with UEFI and hardware virtualization enabled in
  firmware; the current physical candidate is `amd64`.
- A dedicated writable USB drive: **8 GB minimum, 16 GB or more recommended**.
  The image uses free space after the read-only live system for encrypted data.
- **8 GB system RAM recommended** for the live host and nested VMs. More memory
  is useful for large repositories and will be required for future local models.
- Secure Boot disabled for current development images; signed Secure Boot
  releases are not available yet.
- A Debian-supported Ethernet or Wi-Fi adapter. Firmware coverage is broad but
  not universal, so hardware reports are welcome.
- Optional second removable media for explicit document import/export. Session
  filesystems are never shared directly with the host or another session.

Writing the ISO destroys the previous contents of the selected USB. Verify the
device identity before writing it and never test persistence on irreplaceable
media.

## Future: the Oblivion local inference engine

Cloud mode can minimize local traces and network metadata, but it cannot be
fully air-gapped: approved context still leaves the machine for inference. The
planned **Oblivion Local Inference Engine** completes the offline architecture
by adding a dedicated inference VM that never receives a network device.

The intended design keeps the existing boundaries rather than embedding a
model server in the trusted host:

```text
encrypted model media
        │ explicit, verified import
        ▼
local inference VM ── private channel ── session VM
        │
        └── no NIC, no cloud credential, no provider request
```

Model weights, runtime and accelerator access will need their own signed
manifests, memory-erasure tests, update process and hardware matrix. Local mode
will be called air-gapped only after tests prove that the inference path boots
and operates with every external network interface absent—not merely blocked by
a UI setting.

## Project status

| Area | Status |
| --- | --- |
| amd64 live USB boot | Tested on physical hardware |
| arm64 live image | Built; boot, nested KVM and offline Documents validated in UTM on M4 Pro |
| General and per-session LUKS2 persistence | Implemented and tested |
| Offline Documents VM | Implemented |
| Tor and SOCKS5 gateway | Implemented; hardening and UX work continue |
| Abliteration.ai remote inference | Integrated |
| Refuseless remote inference | Integrated through the fixed provider gateway |
| OpenRouter remote inference | Integrated; ZDR-only endpoints enforced per request |
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
bun install --frozen-lockfile --os '*' --cpu '*' --libc '*'

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

### What we want to build next

- Finish the minimal Debian package, service, binary and host-egress audit.
- Expand audited provider support without weakening the per-opening endpoint allowlist.
- Build the offline Oblivion Local Inference Engine and its verified model-import
  workflow.
- Add OnionShare-based, explicitly authorized file exchange without introducing
  a shared session filesystem.
- Design a disposable browser VM with per-session network rules, download
  quarantine and no access to other session volumes.
- Publish reproducible images, signed checksums, provenance and an auditable
  release profile with every debug path removed.
- Expand the physical hardware matrix for Wi-Fi, graphics, keyboards, UEFI and
  nested virtualization.
- Commission an independent security review before recommending sensitive use.

Roadmap items are design directions, not shipped security claims. Proposals
should explain which VM owns the feature, what data crosses each boundary, how
failure is revoked, and what evidence can verify the result.

- Read the [contribution guide](CONTRIBUTING.md) before opening a pull request.
- Explore the [architecture](docs/ARCHITECTURE.md) and current [project status](docs/STATUS.md).
- Open an issue for bugs, hardware reports, UX feedback, or focused proposals.
- Report vulnerabilities privately through GitHub Security Advisories as described in [SECURITY.md](SECURITY.md).

If the mission resonates with you, star the repository and help us test Oblivion on real hardware.

## License

MIT. Copyright notices for upstream OpenCode and Oblivion contributors are preserved in [LICENSE](LICENSE).
