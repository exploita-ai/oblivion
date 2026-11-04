# Oblivion 1.0 architecture

Oblivion is a privacy framework around official agent CLIs. Its two frontends
are the native `oblivion` command and the OpenTUI manager. They use one controller
and the same Safe/storage/network operations. This document describes current
source boundaries; the [roadmap](oblivion1.0-roadmap.md) tracks incomplete paths
and the qualification gates.

## Runtime placement

On desktop systems, the launcher manages a headless Debian controller VM and
connects the calling terminal through a private authenticated relay. On Debian
Live, that controller runs directly on the Debian host. The explicit installed
mode marker selects the latter; a failed desktop startup cannot silently choose
it. Linux vsock requires a fresh private per-boot credential in addition to the
VM endpoint identity.

The outer desktop OS and hypervisor remain trusted for input, display and memory.
A bare-metal Live boot leaves the installed desktop OS inactive. Driver, Wi-Fi,
keyboard and operating-system preference management belong to Debian, not the
Oblivion application archive.

## Storage and ownership

The controller privately mounts one general LUKS2 archive. It contains the Safe
catalog, application settings and separate Safe LUKS2 containers. A Safe volume
has its own encryption key and is mounted only by its Safe VM. There are no
shared folders or host mounts of Safe filesystems.

A Safe owns its workspace, imports, native profiles, canonical chat catalog and
sudo-installed system overlay. Multiple agents in that Safe deliberately share
those files. Different Safes have separate VMs, disks, users at the hypervisor
boundary and gateways. Resource admission occurs before allocation.

RAM-only application mode does not unlock the general archive. It creates new
volatile Safes and keeps credentials/settings in RAM. Read-only archive access
is a distinct mode. Temporary runtime paths use tmpfs; the managed image disables
swap, hibernation and core dumps. These controls do not govern the outer desktop's
swap or backups.

Every opening has a nonce in addition to Safe ID and slot. Socket capabilities,
managed jobs, input activity and cleanup bind to that opening. Close/Lock revoke
access, stop owners, verify termination and remove mappings. Failed cleanup
remains visible as recovery; stale release requests cannot close a later opening.
Inactivity locking counts human input, not output or background execution.

Child creation journals contain a sealed task envelope, not plaintext prompt
text. A separate HKDF domain and XChaCha20-Poly1305 bind it to its family, Safe,
parent, request and requested agent. Unlocking General alone cannot decrypt that
task; the controller needs the family's authorized capability. Status and Share
do not include task content. An explicit `safe task review SAFE --json` opens the
task for review only after the Safe is open. The manager first pins an offline
opening; status and review do not establish a network route. The view escapes
control and direction characters and clears its plaintext on Back, error, lock,
opening change or unmount.

`safe task status/start/retry/cancel` expose the actual managed job, native chat
ID, request identity and attempt count. Start reconciles an uncertain attempt
without allocating a second request. Retry needs a confirmed failed or cancelled
job and explicit confirmation; completed and unknown outcomes are not retryable.
After an interrupted command the UI reads authoritative status before reporting
an outcome. Back leaves the job running, and normal inactivity locking still
applies. Opening the native client does not submit the saved task. Automatic
startup on child creation remains in implementation.
A same-capability password rewrap preserves access; changing the family secret
requires resealing pending tasks as part of the rotation transaction.

## Network model

Each online Safe connects only to its own gateway VM. Application traffic uses
Tor or the selected SOCKS5 endpoint. Public destination DNS resolution happens
through that transport; UDP, IPv6 bypasses, direct DNS and direct connections
are denied. The host's DHCP/Wi-Fi boundary is separate.

Open Internet permits public TCP destinations with explicit deny rules and
address restrictions. Strict requires matching permissions. Offline blocks
provider and tool traffic; an offline guest can have no network device. All
processes in the Safe, including root, are subject to the gateway boundary.

There is no privileged provider route: official clients carry their own provider
authentication through ordinary end-to-end TLS tunnels. Changing transport or
rotating Tor revokes streams and blocks application admission before constructing
the new route. Readiness requires verified transport and isolation observations,
not a settings selection. Failure stays closed. Other Safes have independent
route lifetimes. No automatic external IP-check request is part of readiness.

The manager refreshes observations every five seconds and removes positive
transport state after ten seconds without valid data. Policy and transport are
bound to the current host nonce and the selected Safe's ID, slot and opening
nonce, rather than a global or slot-zero status. Locked, closing, recovery and
changed-opening snapshots cannot carry forward ready marks. A transport mark
also requires a current agent-mode VM and verified isolation. The host-link
indicator is independent and remains available before unlocking; a Safe's policy
is shown beside it only with a fresh matching Safe observation.

Known dedicated telemetry collectors for the pinned clients are blocked. A
hostname gateway cannot classify telemetry mixed with inference traffic at the
same encrypted origin. Tor does not conceal a provider login from that provider.
Cloud mode is not air-gapped.

## Agents and history

Unmodified official Codex, Claude Code and OpenCode 2 binaries run in the Safe.
The launcher passes structured argv, resize, input, signals and distinct output
streams; interactive terminal controls are filtered before they can affect the
outer terminal. Profiles and authentication stay inside that Safe.

A Safe-local watcher reconciles native resume stores with a canonical catalog.
It retains source-native records separately from portable messages and tools.
Native indexers/importers run without an external network route. The current
catalog handles typed content and replayable projection intents; interactive
picker, process-death and per-chat author admission remain acceptance work.
See the [history adapter](../packages/oblivion-history/README.md).

Scoped MCP operations authenticate their calling VM and opening. A task can
create a closed child Safe with provenance and a password inherited through the
family credential design; it cannot choose another Safe's authority, filesystem
or credentials. The intended automatic-child path includes scoped delegation of
only the requested agent's supported provider credential, not its whole home,
profile, history or caches. This work remains in implementation, with API keys,
`CodexAccessToken` and `ClaudeSetupToken` as candidate forms to qualify. Universal
managed OAuth reuse or refresh is not promised. The controller must authorize
the transfer; task text, public status and MCP responses never carry the secret.
Native login is the fallback when a credential cannot be delegated. Managed
chat jobs use bounded output, timeouts and controller
cleanup ownership. They do not weaken native permission prompts silently.

## Transfers, backups and Share

Copy operations use fixed private ports, paginated metadata, approved manifests,
hashes and receipts. A desktop selection grants only the selected bytes.
External removable filesystems are parsed in separate offline media VMs, not in
the controller or Safe. No copy grants a permanent shared directory.

A personal backup copies a closed encrypted volume and may include native
provider credentials. The immutable offline SafeAdmin checkpoint records child
origin, sealed task and attempts inside `/vault/state/oblivion/safe.json`, without
running the sudo overlay or history watcher. Raw restore authenticates the volume
password/token and task context without the mother, retains original identity,
family and data key, and publishes with an Offline profile. The native backup
CLI is still in implementation, and the actual VM round trip remains a gate.
Share is a different, versioned portable package: selected
workspace/imports, canonical conversations and approved relationships, encrypted
with a separate passphrase. Known credential stores and installed-system overlays
are excluded. Content scanning is best effort and explicit review remains
necessary.

Share maintenance uses an offline immutable profile that bypasses the Safe's
sudo overlay. It must not run agents, jobs, shell startup files or native imports.
The controller relays metadata and private streams; the desktop writes only the
ciphertext Share container. Import stages into fresh unpublished Safes; all
payloads and the final age authentication chunk must pass before publication.
The controller publishes an imported collection by one no-replace directory
rename; the ordinary Safe resolver covers both locally created and imported
Safes. Imports allocate new identities, family descriptors and volume keys and
start with Offline policy. They never replay a native login profile. Pending
imports require explicit recovery after lock or restart. Batch export authority
is leased, bound to the host opening and restricted to a fixed source set;
sources are reviewed and streamed one at a time. Two-installation acceptance
remains open. [User workflow and recovery](SHARING.md).

OnionShare has independent gateway/file VM ownership and cancellation. Ordinary
files and closed personal backups use separate positive selections. Public
large-backup acceptance remains a release gate.
