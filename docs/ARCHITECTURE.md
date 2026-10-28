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
SOCKS5 proxy. Destination names are sent to that transport for remote
resolution (`socks5h`); both the broker and tool client reject local resolver
use. The external proxy itself must be configured as a numeric IPv4 endpoint.
There is no direct fallback. An application that ignores the controlled proxy
cannot obtain an alternative route.

Application UDP is blocked, including direct DNS, QUIC and NTP. The connector
supports SOCKS CONNECT, not UDP ASSOCIATE. Direct DNS over TCP and DoT are also
blocked for application identities. DoH can only be reached as an authorized
HTTPS destination through the selected transport. Host DHCP and link-layer
ARP/Wi-Fi authentication establish the local connection; the gateway's
connection to Tor relays or the chosen proxy is its only public TCP path.
These restrictions apply inside Oblivion; a surrounding Mac/Windows/Linux
host is outside its network policy.

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
- The [operational milestones](STATUS.md#ordered-milestones): interactive
  terminal/processes, USB/virtual-media intake, conversation exports, encrypted
  session backup/restore, redacted diagnostics and OnionShare receive/share.
  These are planned additions, delivered in stages;
  the current implementation list remains in [STATUS.md](STATUS.md#implemented).

Out of the active roadmap: native OS ports and native Mac encrypted storage,
replacement of gateway/transfer VMs with host processes, llama.cpp, local
models/downloads, GPUs, DGX Spark, inference nodes, air-gap deployment workflows,
HuggingBay/torrents, live copies between sessions and simultaneous protected
sessions. No GPU passthrough or inference VM work.
The additional Files/Git UI, browser/project previews and MCP
integrations are also deferred for now, with no scheduled delivery milestone.
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

Disable automatic shared folders, host filesystem integration and unnecessary
device passthrough in the supplied profile. Host/guest text clipboard sharing
is an explicit VM profile option. The trusted display uses a restricted
Wayland/SPICE adapter with Debian's broker, or the pinned VirtualBox clipboard
client on amd64. Neither the compositor socket nor the hypervisor device is
available to session VMs. Guest terminal clipboard escapes stay filtered;
copy requires a manager selection and paste is a user action. The SPICE
adapter serves only UTF-8 text up to 256 KiB and fetches host bytes lazily on
paste. Its broker runs as the display user with a fixed virtio device and no
network, uinput device, session files or general vault. Native desktop/clipboard
history on the outer OS is outside this boundary. Document and test explicit
transfers separately. Clipboard copying deliberately releases the selected
text to the outer host. Import/export must work with tested media or
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

The table below retains the foundational release gates. The active feature
sequence is [M0–M5 in STATUS.md](STATUS.md#ordered-milestones), updated on
2026-10-28. It adds terminal, transfers, exports, backup/restore and OnionShare
while retaining the Debian host, gateway, session and transfer boundaries.

| Step | Work | Exit evidence |
| --- | --- | --- |
| 1. Finish the focused audit | Debian/controller, inner VMs, provider and tool requests, credentials, filesystem writes, network policy and outer-VM integration. Stop native-vault and GPU research. | [Source audit and targeted tests completed](STATUS.md#audit-results); ranked defects and pending runtime qualification are recorded separately. Full-image tracing and destructive VM tests remain release gates. |
| 2. Protect persistence and recovery | Exercise general/session vaults, multi-chat history, transfer interruption, low disk, normal/forced shutdown and upgrades. Fix measured defects first. | Real chat/file contents survive close/reopen, Debian reboot and outer-VM stop/restart. Wrong passwords and failed cleanup cannot falsely report success. |
| 3. Complete API and transport reliability | Keys/grants, selected provider, Tor bootstrap, SOCKS5, certificate checks, cancellation, network loss and controlled tool egress. | Real agent file task plus invalid-key, provider-error, proxy/gateway-failure and bypass tests; no direct fallback or stale protection status. |
| 4. Finish setup and delivery usability | Existing TUI polish, automatic internal services, live persistence and tested VM import/profile, correct resource checks, Documents and explicit transfers. | Fresh setup to useful work and later recovery through the product UI. Keyboard, mouse, existing copy/paste, resize and scroll pass on each declared profile. |
| 5. Minimize, qualify and release | Remove only audited unnecessary Debian packages/services, check release/debug separation, build artifacts/manifests/signatures and test upgrades/rollback. | Physical amd64 and declared virtualized profiles pass full regression. At least five non-author testers across qualified paths complete the workflow without developer repairs; publish unsupported combinations and review status. |

The [completed source audit](STATUS.md#audit-results) sets the fix order:
chat startup/recovery, durability, complete teardown, legacy upgrade safety,
then transport/key reliability. Finish runtime leak/egress qualification before
producing a new candidate. The operational additions use the same boundaries.
No native port, archive conversion or new ISO is produced merely by updating
this plan. Use disposable fixtures and copies;
do not alter the user's running VM, personal archives or host networking for
audit convenience.

### Operational feature boundaries

Chat, Documents and Terminal are views of the same protected
session. A terminal runs as an unprivileged process inside that session VM,
independent of a provider key. Offline terminal access preserves the offline
guest's absent network device and agent. Moving an offline guest to chat still
requires an orderly VM transition: report and stop its running processes
before restarting on the same unlocked volume. During chat, view changes keep
the agent and selected jobs alive. Close/lock stops all of them and confirms
teardown before closing the volume.

USB/virtual-media imports and OnionShare uploads converge on
the existing manifest/approval/verified-copy boundary. Remote intake is staged
with a storage quota in RAM or encrypted storage, outside the active workspace.
The manager receives metadata; an approved copy publishes files into session
`imports`. Untrusted files are not opened or extracted on arrival. Uploading
or sharing session files requires an explicit selection and destination.

Encrypted session backups are controller-owned exports of a closed LUKS2
container with compatible encrypted session metadata. They are separate from
document export and have independent streaming/size limits. Restore preserves
the source, refuses unsupported formats and validates the copy in an offline
guest, keeping one open session at a time. Provider keys stay in the general
vault. Markdown/JSON conversation exports are deliberate readable disclosures;
diagnostic exports contain only approved metadata, never a VM-memory dump.

Backup preparation checkpoints versioned metadata inside an offline session,
then stops that VM and closes its mapping. A nonroot descriptor-only sender
streams the ciphertext to the existing export VM; the host never mounts the
session filesystem. Restore reverses this boundary: the read-only import VM
offers one selected encrypted file, and a nonroot receiver writes only a new,
empty inherited descriptor inside the general vault. Its independently bounded
copy authority does not widen ordinary document transfers. The controller saves
a durable private receipt before acknowledging a complete copy. After source
detach, a separate password operation opens that disposable copy in an offline
guest, checks the format/database through private snapshots, closes it again
and publishes a fresh archive entry without replacing an original. Failed
passwords leave the verified copy retryable; cancellation deletes only the
new pending copy. After a crash, unfinished entries remain explicitly
discardable. Transport completion alone never publishes a restored session.

Conversation export uses a fresh, controller-authorized virtio port and a
nonroot maintenance service inside the active session VM. SQLite backup makes
a consistent copy including WAL commits on the session volume. An isolated,
unregistered OpenCode server reads that copy using its own export API, without
provider credentials, configured extensions or execution recovery. Its private
network namespace exposes only loopback. The controller receives bounded
chat-list metadata or the generated path/size, never the transcript. Readable
outputs are capped at 64 MiB, published only after a complete write/flush and
never replace an existing file. Private snapshot/runtime directories and
unfinished outputs are removed after that operation's service stops; boot
cleanup covers an interrupted VM. Per-operation service instances avoid
reusing a still-stopping service when Linux reuses a virtio port number.
Diagnostics take a separate controller-owned allowlist of enum/boolean/numeric
platform and lifecycle fields, previewed before an explicit export. Full
status objects, arbitrary error strings, paths and logs are not serializable
as a diagnostic report.

OnionShare's network-facing file service belongs in the transfer boundary.
Tor service publication remains under the gateway's authorized lifecycle; the
implementation must qualify its dedicated service/control channel without
giving a session raw Tor administration or broker credentials. Private
transfer addresses/keys are temporary and stop on completion, cancellation,
timeout or lock. An OnionShare operation has its own verified Tor status and
does not silently change a SOCKS5 inference selection. Expanding host firewall
egress for a transfer VM is not part of this design.

The M4 gateway implementation is a separate Tor-only profile, with no model
credential/broker or SOCKS listener. Its private virtio controller permits only
initialization, bootstrap/observation, selective infrastructure snapshots,
fixed-backend authenticated publication and shutdown. The backend is
`10.89.0.2:8080` on its own point-to-point wire; forwarding stays disabled and
the file selector stays empty before publication. A Tor-owned control
connection uses `TAKEOWNERSHIP`, so controller death terminates the dedicated
daemon. Cleanup restores the empty firewall selectors even after abnormal
termination. The host still has to confirm complete gateway/file-VM teardown
before claiming a lock. The separate file VM now has a single private NIC, no
default route, a root lifecycle controller, an AF_UNIX-only HTTP worker and a
bounded unprivileged socat relay. Sharing uses a verified snapshot sealed and
bound read-only into the HTTP unit. Review stops/reaps the relay and worker,
then exposes the actual frozen intake only through the existing copy endpoint.
Seven real private-wire guest scenarios cover these paths and controller
failure/expiry. The Linux host owner now connects preparation, receive
publication, revoke/freeze, approved session copy and close cleanup in source.
The manager now generates a RAM-only recipient pair and connects receive/review
to the retained Documents picker and manifest confirmation. Sharing from session
files now uses the same approval boundary in the reverse direction. A public
ARM64 laboratory has passed independent recipient authorization, upload,
approved import/reopening, selected-file download, revocation and ephemeral
archive byte identity. Supported-image acceptance remains separate. The state store requires a `Model` or `Transfer` purpose:
it preserves legacy `profile/tor-state` and isolates transfers in
`profile/onion-tor-state`, with no fallback or proxy/profile writes. The owner
checkpoints only selective transfer infrastructure state and respects the
writable/ephemeral policy.

The network-only QEMU uplink reuses the existing user/stream/hub backend without
a machine, CPU or disk. Its source launcher retains the host's existing
public-uplink identity; Tor and file VMs use distinct UIDs, AF_UNIX-only access
and private network/PID namespaces. The network-only actor also has a private
PID namespace so it cannot inspect the legacy model hypervisor with the same
uplink UID. Only Tor receives the private NAT wire; the file VM stays on its
separate inside link. All auxiliary units are bound to one root-only owner;
exact peer/session pidfds and a dedicated session lifetime monitor avoid
numeric-PID reuse and console/QMP contention.

Receive publication requires a canonical recipient public key, current Tor
bootstrap/isolation and an acknowledged HTTP worker. The recipient private key
never enters the owner/gateway/file protocols; only an explicit manager action
reveals it. Its owned byte buffer is cleared on disposal, without claiming
complete erasure of copies made by the managed runtime or terminal. Bounded background file RPCs
leave the ownership loop available for Tor heartbeats and cancellation. Before
review, the owner confirms Tor shutdown/revocation, reaps the network actors
and waits for sealed intake. A separate manager-UID socket then reuses the
ordinary browser/manifest/hash/approval protocol to import selected files. It
never mounts the session filesystem on the host or stages payloads there;
receipt delivery waits for session-port removal. File/copy threads are joined
before cleanup removes the port. Polling returns metadata only; the temporary URL
is an explicit separate response and stays out of job/profile files. Close,
lock and expiry reap the auxiliary units before storage closure. Configuration
is optional for older controllers and included in newly built Live images.
The existing distributed candidate is unchanged. The Tor/file hypervisors use
UIDs 1105/1106; UID 1104 remains reserved for display/input.

Encrypted backup sharing is a separate authority from the 256 MiB document
copy path. The controller checkpoints metadata offline, stops the session VM
and closes its mapping. It passes one already-open O_RDONLY LUKS2 file to the
file hypervisor using QMP/SCM_RIGHTS, as a read-only virtio block device. The
hypervisor gets no general-vault directory and the guest never decrypts or
mounts that device. Its unprivileged HTTP worker verifies the read-only device,
size and LUKS2 header, then reuses the pinned upstream streaming/Range handler
without eager hashing, compression or RAM staging of the whole container.
The fixed filename is `session.oblivion`; the independent limit is 1 TiB and
one hour. A backup owner watches the storage controller instead of a session
VM. Session opening/mutation is blocked during this share. Cancellation, expiry
or general lock revokes publication and reaps the hypervisor/descriptor before
storage closure. The user explicitly authorizes preparation and confirms
publication separately. No session password enters a transfer guest or URL.

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
