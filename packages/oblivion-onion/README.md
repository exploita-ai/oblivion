# Isolated OnionShare worker

This GPL-3.0-or-later component adapts OnionShare 2.7's production Web, Flask,
Waitress, multipart and archive implementations. It runs as a separate process
inside the file-transfer boundary, never in the session, model broker or host
manager. The manager and Linux controller integrate receive/review/import,
selected-file sharing and closed-session ciphertext sharing. Actual disposable
Linux hosts with independent public Tor clients have passed receive, approved
import, reopening, selected-file download, revocation and ephemeral-storage
checks. Large backups also pass private-wire streaming/resume tests; full public
backup qualification is tracked in [STATUS.md](../../docs/STATUS.md).
These laboratories do not establish supported ISO/UTM/KVM/physical-media
acceptance or reliability on other Tor networks.

The upstream CLI's `--local-only` output is not a production credential. This
worker never constructs upstream's Onion/OnionShare CLI network objects. Only
the separate gateway may publish a fresh authenticated onion service; the file
worker gets neither Tor administration nor a provider credential.

## Runtime contract

- UID 1000, a read-only root, no capabilities/core dumps/swap, bounded memory,
  process count and RAM staging. The VM supervisor must enforce these limits
  and destroy the VM if teardown cannot be confirmed.
- `/run/oblivion-onion` is a private, UID-1000-owned tmpfs directory. The worker
  refuses persistent storage and never removes a directory it failed to claim.
- For sharing, the verified copy endpoint stages only approved files/folders
  under `share/` before startup. No live session mount or shared host folder.
- Start the Python environment in isolated mode with a clean environment:
  `/opt/oblivion-onionshare/bin/python -IB /usr/lib/oblivion/onion/service.py`.
  FD 3 is an inherited supervisor-owned Unix socket (`--control-fd` may select
  another inherited FD). Both standard output streams must go to `/dev/null`;
  the worker also discards them before loading upstream.
- The HTTP listener is the private `http/service.sock`, mode 0600. A separately
  confined relay may expose it only on the dedicated gateway/file-VM wire.
  `serving` means that this Unix listener is available, not that Tor is ready.
- The supervisor must remove gateway publication before accepting `freeze` as
  a review boundary. Freeze stops HTTP and joins the request worker before
  returning completed-file metadata. The verified copy endpoint then reads
  approved files under `receive/`. No automatic publication to the session.
- Stop, expiry or a lost control channel remove this operation's RAM staging.
  On an unconfirmed stop, the supervisor must revoke and reap the entire VM;
  do not report a successful lock solely from this worker's status.

The version-1 private protocol is newline-delimited JSON. The initial command:

```json
{"op":"start","mode":"receive","max_bytes":268435456,"max_files":1024,"ttl_seconds":3600}
```

`mode` is `share`, `receive` or `backup`. Ordinary documents are bounded to
256 MiB, 1,024 entries and one hour. Backup mode instead permits exactly one
closed LUKS2 volume of 32 MiB through 1 TiB for at most one hour. Limits may
be reduced. A successful response contains only
`ok: true` and a `status` object: `state`, `mode`, `files`, `bytes`,
`transferred_bytes`, `rejected`. Commands `status`, `freeze` and `stop` take
only their `op` field. Freeze additionally returns relative received-file paths
and sizes. `handoff` is receive-only: it freezes HTTP, exits and leaves completed
files in RAM for the supervisor to reap the unit and seal the intake. The
supervisor discovers actual files independently; worker paths are not filesystem
authority. Errors are fixed codes; no upstream request/exception text is sent.
This protocol is private and does not change OpenCode's public API.

Received names follow upstream's `secure_filename` normalization. The review
must show the resulting names. Duplicate/empty normalized names, malformed or
incomplete uploads and quota violations are refused. Files are not executed,
previewed, unpacked or moved into a session by this service.

Backup mode reads only `/dev/oblivion-backup`, supplied by the privileged
supervisor as a read-only block device. The worker verifies the device type,
kernel read-only flag, LUKS2 header and bounded size before serving it as
`session.oblivion`. It reuses upstream HTTP streaming and single Range support,
without eager whole-volume hashing, gzip preparation or RAM staging. Werkzeug
validates ranges, including suffixes and starts beyond EOF. This worker never
receives a password, decrypted mapping or general-vault directory. Receiving a
large backup directly over Tor is not implemented; restore currently reads
USB or prepared virtual media through the existing verified-copy path.

## Locked dependencies and tests

The build consumes the reviewed `script/oblivion/onionshare-requirements.lock`,
the upstream version/wheel descriptor and supplemental license source hashes.
Only Stem's source-only release is built from source; its build environment is
also pinned. There is no runtime pip/install/update path. The environment keeps
all 47 dependency versions, source URLs/hashes, license files and install
reports in `/opt/oblivion-onionshare/`. Updating upstream requires regenerating
and reviewing the lock and repeating the adapter tests.

Build `onionshare-test` from `script/oblivion/Dockerfile.vm-lab`, then run the
same confinement as CI:

```sh
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 96 --memory 512m --memory-swap 512m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777 \
  --tmpfs /run/oblivion-onion:rw,nosuid,nodev,noexec,size=96m,mode=0700,uid=1000,gid=1000 \
  oblivion-onionshare-test
```

These tests use synthetic files and the real upstream HTTP service over Unix
sockets. They cover download/range/ZIP, containment and links, upload review,
byte/file quotas, duplicate/malformed/incomplete requests, control-owner death,
expiry, clean output streams and persistent-runtime refusal. Both architecture
jobs are registered in `Oblivion checks`. This does not replace real Tor
sender/recipient, VM, revoke-on-lock or supported-image acceptance.

## Dedicated file VM

`packages/oblivion-transfer` provides the separate MIT-licensed
`oblivion-onion-file` supervisor. `guest/` contains its production systemd,
socket activation, network, copy endpoint and confinement profile. The image
has one private NIC (`10.89.0.2/30`), no default route, DNS, Tor, model client,
provider credential, writable disk or shared filesystem. Its firewall permits
only gateway requests to TCP 8080 and UID-1000 established responses. A bounded
`socat` relay connects these requests to the private HTTP Unix socket. The
HTTP worker itself has a separate network namespace and AF_UNIX only.

The root-only `oblivion.onion.file` virtio port uses four-byte big-endian JSON
frames, version 1, with hello role `onion-file`. Fixed operations are
`backup`, `prepare-share`, `share`, `receive`, `observe`, `freeze`, `source`, `shutdown`.
The controller polls at least every five seconds; idle ownership expires after
15 seconds and a started operation has a TTL of at most one hour. No peer can
choose a listener, source root, system command or privileged service name.

Sharing first starts the existing receive endpoint on `oblivion.onion.stage`.
After the verified copy completes, `share` accepts its `receipt`, original
selected `paths` and `ttl_seconds`. It verifies the on-disk receipt, original
manifest hash and complete snapshot before sealing it. The HTTP unit sees a
read-only bind mount of that snapshot; neither HTTP nor the copy user can
modify it. Live session files are never mounted in this VM.

Receiving starts without a session or API key. The host must revoke gateway
publication before requesting review. Independently, `freeze` stops/reaps the
TCP relay, hands off and reaps the HTTP unit, scans the actual intake and
seals it for the separate copy UID. Only then can `source` start the existing
paginated browser/send endpoint on `oblivion.onion.source`. There is no
automatic publication to a session. A failed endpoint, controller exit or
unconfirmed cleanup powers off the disposable VM; the host must still verify
VM termination before claiming completion.

Build `Dockerfile.transfer` into `artifacts/ci/transfer`, then the
`onion-file-artifacts` target from `Dockerfile.vm-lab`. Run
`script/oblivion/run-onion-file-lab.py --image <directory> --output <new-directory>`
on Mac ARM64 HVF, or add `--accelerator tcg` on Linux. It verifies image and
source hashes before boot. Ten actual two-VM scenarios cover read-only
sharing, upload/freeze/approved copy, killed/disconnected owners, malformed and
partial requests, expiry, raw backup streaming/resume and writable/invalid
backup refusal. The 512 MiB block fixture for these file-only tests contains
synthetic bytes with a LUKS magic marker, not a real encrypted archive.
The fixed HTTP peer has only the private wire,
not an external network. Production and diagnostic images are separate.
The test allocates 1,280 MiB to the file VM; it is not a measured peak or proof
that the complete candidate fits the baseline RAM profile. Complete public
backup and supported-candidate acceptance remain separate gates.

## Dedicated transfer Tor gateway

`oblivion-onion-gateway` is a separate Rust supervisor and Debian gateway
profile. It does not run the model broker, egress connector or tool proxy, has
no SOCKS/DNS listener and accepts no provider credential. Its only data backend
is `10.89.0.2:8080` on a separate point-to-point file-VM wire. The kernel never
forwards packets. Only Tor UID 1200 may use the public uplink; the file backend
remains blocked until private publication is authorized. The default policy
and all cleanup paths have empty Tor/file selectors.

The private root-owned virtio port is `oblivion.onion-gateway`. Frames use a
four-byte big-endian JSON length, bounded to 512 KiB. The initial response is
`{"ready":true,"version":1,"role":"onion-gateway"}`. Requests use an
`operation` field: `initialize` with optional selective guard `state`, `enable`,
`observe`, `snapshot`, `publish` with a canonical base32 X25519 public
`client_auth` and `ttl_seconds` (1–3,600), or `shutdown`. No arbitrary target,
Tor command, API key or detached-service option exists. The host must poll at
least every five seconds; a missing control heartbeat expires within 15 seconds.

Publication requires verified firewall state and 100% Tor bootstrap. It creates
an ephemeral ED25519-V3 service with mandatory V3 client authorization and
`DiscardPK`; the service private key is never requested. The client private
authorization key belongs in the trusted manager's RAM and is not sent to
this gateway. `TAKEOWNERSHIP` ties Tor's process lifetime to the supervisor's
control connection, including abrupt controller death. Shutdown revokes the
service, stops/verifies Tor and returns only selected infrastructure state for
encrypted persistence. The host must still reap both VMs before reporting a
completed session close/lock.

`observe.tor_ready` describes Tor bootstrap/isolation, not recipient reachability
or descriptor propagation. Independent recipient/authentication and file-copy
round trips are tested separately. Transfer guard state stays
separate from the model gateway's profile state;
a model configured for SOCKS5 must not be reconfigured by an OnionShare action.
The host store has explicit model/transfer purposes and separate legacy
`tor-state` / new `onion-tor-state` files. The source owner now loads and
checkpoints transfer guards independently, including after revocation, and
respects the general vault's writable/ephemeral policy. It never updates a
model transport, proxy credential or provider key.

## Host owner

The optional root configuration `onion` contains `gateway` and `files` VM
configurations with the existing VM schema. Missing configuration preserves
previous behavior. New Live build definitions include both profiles; already
built/distributed images are unchanged. The
`oblivion-onion-host.service` launches a machine-less NAT actor, the dedicated
Tor VM and the file VM. Only the NAT actor uses the existing public-uplink UID;
Tor/file hypervisors have distinct UIDs, private PID/network namespaces and
AF_UNIX only. The NAT actor has no machine, CPU, kernel or block device, and
cannot inspect the legacy model hypervisor through its private PID namespace.
The host display keeps UID 1104; gateway/file hypervisors use 1105/1106.
Actual Linux laboratories check namespaces, egress and actor teardown;
supported-candidate acceptance remains required.

The authenticated private controller operation `onion` accepts strict JSON:
`prepare` with `ttl_seconds`, `status`, `receive` with a canonical public
`client_auth`, `stage`, `share` with `client_auth`, `access`, `freeze`, `import`,
`prepare-backup` with `id`, `password` and `ttl_seconds`, or `cancel`.
Ordinary preparation requires an open
session but no provider key or model gateway. It publishes nothing. Receive
requires fresh verified Tor readiness; only after the file worker acknowledges
startup does the owner request fixed-backend authenticated publication. The
manager generates a fresh X25519 recipient pair in RAM and sends only its
public key. The private key is hidden until an explicit reveal and its owned
byte buffer is cleared on revoke/cancel/handoff. No private key is stored in a
job, guest, environment, argument or file; managed-runtime memory erasure is
not a guarantee that all prior string/render copies are overwritten. Status contains bounded phases/counters
and Tor observations; an onion URL is returned only by explicit `access`, kept
in RAM and never included in the job file, status polling or guard profile.

File startup/freeze use one bounded background RPC while the owner maintains
Tor checkpoints and session/guest ownership checks. There is no concurrent
reader on the same file-control stream. Freeze first confirms Tor shutdown and
revocation, then starts file freeze while stopping/reaping the two network
actors. `review` is reported only after the file supervisor confirms that the
relay/HTTP worker are gone and actual intake is sealed. The source `import` action now opens the sealed source endpoint and the active
session's fixed import receiver. A manager-only socket reuses the existing
paginated browser, manifest approval, hashing, import publication and receipt
protocol. It exposes metadata to the manager and streams payload bytes without
staging them on the host filesystem. Copy receipt delivery waits for removal
of the temporary session port. Intake remains private until copy approval.
Expiry, cancellation, session death and close/lock stop every auxiliary unit
and verify exact peer pidfds before allowing storage closure. Cleanup reaps
both file-control and copy threads before removing the temporary session port.
The owner runtime is root-owned mode 0711 for socket traversal: its control
socket is root-only 0600, and its separate copy socket is 0600 owned by the
configured manager UID. Other users cannot create/list entries or connect. Failed cleanup
cannot report a locked session. Both Linux architectures compile; the current
public recipient laboratory uses ARM64 HVF with nested TCG and synthetic data.

For backup sharing the root controller briefly opens the selected session
offline to checkpoint its encrypted metadata, stops the session VM and closes
its LUKS mapping. An already-open O_RDONLY ciphertext descriptor is passed via
QMP/SCM_RIGHTS to a read-only virtio block device in the file VM. No host or
guest path supplied by the manager becomes a disk authority. A reserved PCIe
root port permits hotplug on both QEMU machine families; per-role RAM locks
serialize monitor setup. Session opening/mutation remains blocked until the
owner revokes publication, reaps its guests and releases the descriptor.
During this operation owner liveness follows the authenticated storage
controller's pidfd, since the session VM is intentionally closed. Preparation
and publication have separate confirmations in the manager.

The `onion-tor-test` target exercises actual Tor service creation, fresh IDs,
revocation and process exit after disconnect/SIGKILL, with networking disabled.
`onion-control-artifacts` additionally produces the production gateway and an
explicit diagnostic image. Run `script/oblivion/run-onion-lab.py` against that
image with `--image`/`--output`; use Mac ARM64 HVF or explicit Linux TCG. It
checks systemd hardening, keyless initialization, not-ready publication refusal,
normal shutdown, owner death/disconnect, malformed/partial frames and firewall
tampering. Images have no writable user disk and QEMU blocks external access.
Both tests are registered in CI; the guest control laboratory runs on ARM64.

## Source manager receive flow

`Documents / Receive over Tor` prepares the dedicated path, waits for verified
bootstrap and automatically starts the private receiver. The temporary address
and an explicitly revealable access key are for Tor Browser's client-authentication
prompt. No key is pasted into a command. Current transfer observations expire
within ten seconds even when the next poll is still pending. This transfer
status is independent of the model gateway's Tor/SOCKS5 indicator.

`Stop receiving and review` revokes the address and seals intake. `Choose files
to import` reuses the existing Documents picker and explicit manifest/copy
confirmation. Cancellation owns the OnionShare job rather than a removable-media
transfer. Renderer tests cover both terminal sizes, startup cancellation,
unconfigured images, hidden keys and handoff into the existing approval flow.
Native Unix-socket tests use the real file sender and session import endpoints;
they are not an integrated Linux owner or public Tor acceptance result. The
optional image configuration remains off until those runtime gates pass.
