# Oblivion 1.0 architecture

Oblivion is a privacy framework around official agent CLIs. Its two frontends
are the native `oblivion` command and the OpenTUI manager. They use one controller
and the same Safe/storage/network operations. This document describes current
source boundaries; the [roadmap](oblivion1.0-roadmap.md) tracks incomplete paths
and the qualification gates.

## Runtime placement

The launcher manages a headless Debian controller VM on desktop systems and
Debian Live, connecting the calling terminal through a private authenticated
relay. The controller package belongs inside that VM. External Linux has no
direct-controller bypass. Linux vsock requires a fresh private per-boot
credential in addition to the VM endpoint identity. Live presents only its
reviewed data partition to the controller; RAM-only runs do not attach it.

The outer desktop OS and hypervisor remain trusted for input, display and memory.
A bare-metal Live boot leaves the installed desktop OS inactive. Driver, Wi-Fi,
keyboard and operating-system preference management belong to Debian, not the
Oblivion application archive.

## Storage and ownership

The controller privately mounts one general LUKS2 archive. It contains the Safe
catalog, application settings and separate Safe LUKS2 containers. A Safe volume
has its own encryption key and is mounted only by its Safe VM. There are no
shared folders or host mounts of Safe filesystems.

A Safe owns its workspace, imports, native agent histories and profiles, and
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

Each client owns its conversations, native IDs, tools and resume behavior.
Agent wrappers directly execute the pinned official binary; no watcher,
canonical conversation database, prompt-admission hook or cross-agent
projection runs in the Safe. Native job supervision and Safe cgroups retain
process cleanup independently. Share reads only the supported native transcript
formats and restores them for their original agent. OpenCode imports are staged
until its next explicit launch; offline maintenance never runs a client.
See [native history transfers](../packages/oblivion-history/README.md).

Scoped MCP operations authenticate their calling VM and opening. A task can
create a child Safe with provenance and a password inherited through the
family credential design; it cannot choose another Safe's authority, filesystem
or unrelated credentials. The automatic-child path includes scoped delegation of
only the requested agent's supported provider credential, not its whole home,
profile, history or caches. API keys, separately provisioned Codex Access Tokens
and Claude setup-tokens have source adapters; installed-VM/provider qualification
remains open. Ordinary managed OAuth refresh caches are not cloned. The controller authorizes
the transfer; task text, public status and MCP responses never carry the secret.
Native login is the fallback when a credential cannot be delegated. The startup
thread carries metadata and a sealed credential while booting, installs it in
the offline child, then starts the protected agent VM and admits the immutable
task using its stable request ID. Every transition rechecks the parent opening,
VM owner and branch. Failure cleans only the owned child opening/branch;
unfinished cleanup remains explicit. Startup cleanup preserves RAM volumes
until branch/host locking, and normal inactivity locking still stops work. Managed
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
running the sudo overlay or agent processes. Raw restore authenticates the volume
password/token and task context without the mother, retains original identity,
family and data key, and publishes with an Offline profile. The native backup
CLI and manager are implemented; the actual VM round trip remains a gate.
Share is a different, versioned portable package: selected
workspace/imports, original-agent native conversations and approved relationships, encrypted
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
