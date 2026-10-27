# Oblivion architecture

This document describes the intended security boundaries of Oblivion. It is a
design description, not a claim that the current beta image is secure.

The first sections describe the current live implementation. The
[remote-API beta plan](#remote-api-beta-plan)
below distinguishes the retained architecture from work still needed for beta.

## Current system boundary

Oblivion is a dedicated Debian live image, not a desktop application installed
on the user's normal operating system. The image contains a deliberately small
set of Debian packages plus the Oblivion host services and an OpenCode-derived
coding agent.

```text
physical machine
└── read-only live system
    ├── tmpfs runtime
    ├── encrypted general vault
    ├── Oblivion manager
    ├── egress gateway VM
    └── one active session
        ├── independent encrypted volume
        └── isolated session VM
```

The live host owns boot, display, input, encrypted-volume lifecycle and VM
lifecycle. A session VM owns the agent process and the session filesystem. The
gateway VM is the only supported network path for a chat session.

## Persistent state

The general LUKS2 vault stores host preferences, Wi-Fi configuration and saved
provider credentials. Each persistent session uses a separate LUKS2 volume and
password. A session contains its chats, workspace, imported files and the
agent's session-local state.

Only one session volume and one session VM may be open at a time. Locking a
session stops its VM, revokes runtime credentials, closes its encrypted volume
and clears the per-opening API-key override.

Ephemeral mode does not unlock or intentionally modify the general vault. Its
state lives in RAM and is discarded on shutdown. Runtime directories and
temporary files in both modes are placed on tmpfs where possible; this reduces
disk residue but does not protect plaintext while the machine is running.

## Session modes

Opening Documents starts an offline session VM with no virtual network device,
provider credential or agent process. The host receives bounded directory
metadata and file-transfer messages; it does not mount the session filesystem.

Starting a chat stops the offline VM and starts the chat VM against the already
unlocked volume. Chats inside one session share `workspace` and `imports`, but
not another session's volume. Switching between Chat and Documents while a
chat is running changes the view, not the isolation boundary.

External media is handled through explicit import and export flows. The source
or destination is exposed only to the dedicated transfer endpoint. Paths are
validated against the permitted roots and transfers use manifests and content
hashes.

## Network model

The host may have an Internet connection for Wi-Fi, time and gateway setup. A
chat session must not receive a direct host-network interface. Its egress is
routed through the gateway VM using either Tor or an explicitly configured
SOCKS5 proxy. There is no intended direct fallback.

The UI distinguishes three facts:

- whether the host has connectivity;
- whether Tor or SOCKS5 is ready for the active session;
- whether direct session access was verified as blocked.

A selected transport is not considered ready until the controller observes a
working gateway and its isolation checks. Oblivion does not contact a public
"what is my IP" service automatically.

## Credentials

Saved API keys are encrypted in the general vault. The selected key is passed
to the gateway API broker for the current opening. The agent receives a
revocable session token instead of the provider secret. Neither is copied into
the session's durable configuration. Documents mode receives no provider key.

Development images can expose SSH and diagnostic facilities. Release images
must omit them. Test certificates and credentials in the repository are
synthetic fixtures and must never be trusted by a production image.

## Trust and limitations

Oblivion currently trusts the physical machine, firmware, live kernel,
Oblivion host services, virtualization stack and cryptographic implementation.
An attacker controlling those layers can observe an unlocked session.

Cloud mode is not air-gapped: prompts, selected files, tool output and model
responses are visible to the configured provider. Tor hides the source network
from the provider; it does not hide submitted content or make an API account
anonymous. Local inference is deferred; this beta requires a remote provider
for chat and agent execution.

See [SECURITY.md](../SECURITY.md) for the threat model and disclosure process.

## Remote-API beta plan

The beta retains the Debian host and the existing gateway, session and transfer
VM boundaries. On a physical PC, Debian boots directly. In a supported desktop
virtualizer, Debian is the outer host VM and launches the inner VMs. The native
Mac port and removal of the outer VM are no longer active roadmap items.
Local inference remains deferred. This decision changes the plan, not the
runtime, archive format or installed system.

### Product goal and delivery modes

Complete one reliable workflow: boot, prepare encrypted storage, configure a
provider key, open a protected session, use the coding agent and Documents,
then close, lock and restore the same work after restart. Oblivion manages its
internal services; users do not install development dependencies, launch
servers or repair configuration files manually.

One Debian-based product has two delivery modes:

| Delivery | Qualification boundary |
| --- | --- |
| Bare-metal live image | Primary amd64 physical boot path, guided encrypted persistence, minimal Debian and the existing TUI. No outer hypervisor or nested virtualization is needed. |
| Virtualized live image | The same Debian environment in a supported outer VM, using an image matching its CPU architecture. Require actual nested KVM and a writable persistent virtual disk. A booting manager alone is insufficient. |

Keep amd64 and arm64 builds. Qualify each CPU, host OS, hypervisor and version
combination through full session and persistence tests before advertising it.
UTM on the available Apple Silicon Mac is the immediate virtualized test path;
Linux/QEMU and Windows/VirtualBox require their own results. Do not imply that
all Macs or all virtualizers support nested guests. No production software
emulation fallback when required acceleration is absent.

For a qualified virtualizer, supply a verified image and a tested import/setup
profile, or a ready-to-import artifact built from the same release inputs.
The flow must not require manual guest Linux configuration. Installing the
supported virtualizer, granting OS permissions, allocating storage, entering
passwords/API keys and choosing a physical boot device remain explicit user
actions. Do not build a separate native application or custom virtualizer.

### Included and deferred

The beta includes:

- Existing OpenCode coding tools and production chat components; retain the
  current TUI and repair concrete usability defects instead of redesigning it.
- General LUKS2 settings/keys and separate LUKS2 session volumes, titles,
  multiple chats and shared Documents within each protected session.
- One open session at a time, explicit locking, recovery and preservation of
  existing chats and documents during reboot and upgrades.
- Multiple API keys, a global default and a temporary override per opening.
  Persistent settings save encrypted without repeated save/RAM prompts;
  supported ephemeral settings remain temporary.
- Tor by default, optional configured SOCKS5, controlled tool egress and no
  direct or alternate-provider fallback. Start qualification with Abliteration;
  test other already integrated providers separately. No new provider catalog
  or arbitrary endpoint feature is required.
- Offline Documents without a key, network device or agent; bounded import/
  export with progress, cancellation, integrity checks and recovery.
- RAM-backed ephemeral operation inside Debian, with unchanged persistent
  archives. Explain the additional outer-host retention boundary in VM use.
- Clear startup, transport and recovery errors, verified updates and a
  documented restore/rollback path that preserves user data.

Out of the active roadmap: native OS ports and native Mac encrypted storage,
replacement of gateway/transfer VMs with host processes, llama.cpp, local
models/downloads, GPUs, DGX Spark, inference nodes, air-gap deployment workflows,
HuggingBay/torrents, OnionShare, cross-session copies, simultaneous protected
sessions and a disposable browser. No GPU passthrough or inference VM work.
Do not introduce cross-platform abstractions solely for deferred ports.

### Retained architecture

```text
physical PC                         supported desktop host + hypervisor
    |                                           |
    +-- Debian live host            Debian live host VM
           |                                   |
           +--------- same Oblivion services --+
                              |
                              +-- manager and controller
                              +-- encrypted general LUKS2 vault
                              +-- gateway VM: broker + Tor/SOCKS5
                              +-- one session VM + selected session volume
                              +-- transfer VMs when required
```

The gateway and transfer VMs are peers of the session VM, not additional nested
layers inside it. On bare metal there is one virtualization level; running
Debian as an outer guest adds the nested level. The existing controller owns
lifecycle, readiness, grants, close and recovery. The session guest owns its
filesystem and agent. Keep the general vault and other session volumes out of
the agent's reach, and never mount the session filesystem on either host.

Retain Linux cryptsetup/device-mapper, systemd supervision, KVM and current
control/transfer protocols. Audit and repair them in place. There is no native
Mac storage-format feasibility gate or automatic archive conversion in this
roadmap. The outer Mac/Windows/Linux host stores a virtual disk; Debian manages
the encrypted archives inside it. Keep live and VM upgrades compatible and
test on copies before changing any archive or database format/path.

### Outer-VM integration and retention

Detect missing nested acceleration and inadequate resources before creating a
session or waiting for startup. Distinguish unsupported configuration from a
provider or Tor failure. Measure RAM, disk, boot and session-start requirements
on the qualified profiles; neither an ARM64 build nor outer-VM boot proves
usable nested operation.

Use a persistent virtual disk for encrypted archives. Ordinary shutdown must
close the inner session and volumes before shutting down Debian. Qualification
must also cover forced outer-VM termination and later recovery without silently
resetting chat history. Do not use saved-state resume as the normal shutdown
path, and do not rely on snapshots as an encrypted-session backup strategy.

Disable automatic shared folders, host filesystem integration, clipboard
synchronization and unnecessary device passthrough in the supplied profile.
Document and test explicit transfers separately. Offer only a bounded,
user-initiated clipboard path where implemented; it deliberately releases the
selected data to the outer host. Import/export must work with tested media or
explicit transfer endpoints without mounting session files on that host.

Debian's tmpfs/no-swap policy does not control the outer host's swap, diagnostic
files, screenshots, hypervisor logs or saved VM memory. Memory snapshots and
suspend files can contain plaintext and unlocked keys even when the virtual
disk contains LUKS volumes. Audit the supported profile's host-side artifacts
with synthetic markers and state what it cannot prevent. Do not claim that
virtualized ephemeral mode leaves no traces on the physical computer, or that
a Debian VM makes a compromised outer host safe.

### Remote API and network completion

Keep the real API key in the gateway broker, never the session's durable
configuration. Each opening receives a scoped, revocable capability. Close,
lock and failed startup revoke it and clear the per-opening key override.
Changes to active credentials require an orderly stop/reopen. Cancellation
stops local work and access; it cannot prove that a remote provider immediately
stops processing or deletes an already submitted request.

Audit the complete request path, including tool subprocesses, model discovery,
plugins, update checks, DNS, redirects, IPv6 and retries. Provider HTTPS must
validate certificates through either transport. Record the current private
guest-to-gateway HTTP hop accurately; do not describe it as TLS. Assess its
exposure and any required changes against the retained VM trust boundary;
a bearer token or private address alone is not transport encryption. The broker
necessarily handles plaintext within its documented trusted boundary.

Tor startup needs observed progress, bounded waits, cancellation and a clear
retry action. Archive unlock and offline Documents do not wait for Tor. Proxy
negotiation, provider availability and host connectivity remain distinct. No
public IP-check probes or fallback around an unavailable transport. Enforce
Rules for every agent/tool network path, including raw IP, DNS and subprocess
attempts, not only the model SDK. Include the outer VM's networking in tests.

Drive the compact footer indicators from verified controller observations.
Refresh at least every five seconds and discard positive state after ten
seconds without valid observations. A selected transport is not a ready one.
Network details and recovery stay inside the manager.

Trace files and connections with synthetic markers and credentials. Production
has no persistent application content logs; inspect temporary paths, dumps,
service output and dependency writes. Do not retain real prompts, documents,
API secrets or packet payloads in diagnostic artifacts. Report evidence for
tested paths, not an absolute guarantee of no forensic residue.

### Ordered roadmap and deliverables

| Step | Work | Exit evidence |
| --- | --- | --- |
| 1. Finish the focused audit | Debian/controller, inner VMs, provider and tool requests, credentials, filesystem writes, network policy and outer-VM integration. Stop native-vault and GPU research. | [Source audit and targeted tests completed](STATUS.md#audit-results); ranked defects and pending runtime qualification are recorded separately. Full-image tracing and destructive VM tests remain release gates. |
| 2. Protect persistence and recovery | Exercise general/session vaults, multi-chat history, transfer interruption, low disk, normal/forced shutdown and upgrades. Fix measured defects first. | Real chat/file contents survive close/reopen, Debian reboot and outer-VM stop/restart. Wrong passwords and failed cleanup cannot falsely report success. |
| 3. Complete API and transport reliability | Keys/grants, selected provider, Tor bootstrap, SOCKS5, certificate checks, cancellation, network loss and controlled tool egress. | Real agent file task plus invalid-key, provider-error, proxy/gateway-failure and bypass tests; no direct fallback or stale protection status. |
| 4. Finish setup and delivery usability | Existing TUI polish, automatic internal services, live persistence and tested VM import/profile, correct resource checks, Documents and explicit transfers. | Fresh setup to useful work and later recovery through the product UI. Keyboard, mouse, clipboard, resize and scroll pass on each declared profile. |
| 5. Minimize, qualify and release | Remove only audited unnecessary Debian packages/services, check release/debug separation, build artifacts/manifests/signatures and test upgrades/rollback. | Physical amd64 and declared virtualized profiles pass full regression. At least five non-author testers across qualified paths complete the workflow without developer repairs; publish unsupported combinations and review status. |

The [completed source audit](STATUS.md#audit-results) sets the fix order:
chat startup/recovery, durability, complete teardown, legacy upgrade safety,
then transport/key reliability. Finish runtime leak/egress qualification before
producing a new candidate. No architecture rewrite, native port, archive conversion or new ISO
is authorized merely by updating this plan. Use disposable fixtures and copies;
do not alter the user's running VM, personal archives or host networking for
audit convenience.

### Acceptance and honest claims

On every released profile: boot/import, prepare storage, configure a test API
key, open a named session, exchange real messages, authorize a file read/edit,
create another chat, import/export a file, close/lock, reboot and recover both
chats and documents. Repeat with invalid credentials, unavailable provider,
Tor/proxy failure, interrupted startup, controller/guest crash, full storage
and interrupted transfers. Include outer-VM termination on virtualized targets.
Failed cleanup must report recovery, not a locked volume that remains open.

Verify one-session enforcement, wrong passwords, stale/cross-session tokens,
blocked direct egress, key rotation/removal and no content/secret leakage in
observed writes or logs. Compare persistent archives before/after ephemeral
use. Test upgrades/rollback on copies. Run affected package suites, root
`bun run check` and Linux VM/network/transfer integration laboratories when
code changes; read repository testing skills before adding tests. Tie evidence
to the tested revision. Independent security review remains a hardening
milestone, not a claim established by functional beta testing.

Remote inference is not air-gapped: providers receive the submitted context
and tool output. Tor and local encryption do not hide that content or establish
provider retention. Bare-metal live use trusts Debian, firmware and hardware;
virtualized use additionally trusts the outer OS and hypervisor. Do not promise
protection from a compromised trusted host or identical retention guarantees
between physical and virtualized deployment.
