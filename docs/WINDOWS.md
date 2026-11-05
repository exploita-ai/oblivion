# Windows native backend

Implementation checkpoint: 5 November 2026. **The Windows product is not complete
or qualified.** An experimental HCS helper core and owned HCN ICS network are
implemented. A same-user authenticated named-pipe client and shared CLI adapter
are now present. The installed command entrypoint, bundle verification and
resumable protected per-user setup and local Files payload endpoints are connected in source;
ordinary-user admission uses a demand-start SCM broker and owned-resource
recovery uses private receipts. Native UAC setup and reviewed Hyper-V preparation
are connected in source. Pending disk recovery is connected in source; installed privilege and
forced-interruption qualification remain open.
Stopped-only update, software collection and uninstall are now connected in source.
The manager has a Windows x64 build target; its PE
execution and complete installed path still need qualification. This is development
work for phase 8 of the [roadmap](oblivion1.0-roadmap.md), rather than an available product.
No Windows VM has been booted to qualify this source increment.

The source supervisor now elects one private runtime generation and gives each
terminal a lease. It owns the helper process and lifetime pipe; control probes
verify that exact kernel process object, not merely an SID or recorded PID.
The last lease requests guarded shutdown, and only a confirmed helper exit after
HCS/network/grant cleanup permits Stopped. Failed or uncertain shutdown persists
Recovery. After losing the supervisor, recovery requires exclusive journal ownership and
the backend resource lock. An absent pipe alone cannot clear that fence.

## Ordinary-user privilege boundary

HCS and HCN calls run in the privileged helper, while the CLI, manager and explicit
host-side file copies remain in the calling user's process. HCN authorizes calls
against the caller's token, and the HCS create API reserves its security-descriptor
argument as NULL. [HCN authorization](https://learn.microsoft.com/en-us/windows-server/networking/technologies/hcn/hcn-top),
[HCS create contract](https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcscreatecomputesystem).

Elevated setup registers one demand-start LocalSystem SCM service per user SID.
The broker derives `%PROGRAMDATA%\Oblivion\SID` from the Windows known-folder API
and its fixed owner identity. Catalog, configuration and data are administrator/
SYSTEM owned; published software grants the user read/execute only. The service
never executes a helper from a user-writable installation. Client and storage SIDs
are explicit, durable supervisor bindings; process identity is not substituted
for the authenticated user's identity. The election mutex uses the global object
namespace so setup and Session 0 share the same maintenance exclusion.

The broker admits only describe, acquire, resident-start, stop and recovery for
that caller's runtime. Requests contain no SID, helper path, shell command or HCS
configuration. Before sending a request the client verifies the protected SCM
object, its LocalSystem configuration and the pinned running service process.
It queries no foreign process token and receives only metadata/synchronization
process rights. After reading the request, the local pipe server impersonates
the actual caller, checks its SID and reverts before privileged work. Each terminal
holds one broker channel and supervisor lease; EOF cancels pending startup and
releases only that terminal. Ordinary service rights allow start/query, not
configuration changes or service stop. [Service access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights),
[pipe access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights),
[client impersonation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient).
These paths are connected in source. Real SCM installation, ordinary-user use,
pipe/ACL execution and nested Hyper-V boot still require Windows qualification.

## First target: Windows 11 x64 with an HCS-owned Hyper-V VM

Start with Windows 11 Pro/Enterprise, Intel VT-x/EPT or AMD Ryzen/EPYC, firmware
virtualization enabled, and a headless controller created through Host Compute
System (HCS). This is a real Hyper-V VM, owned by Oblivion, rather than a WSL
distribution or a software-emulation fallback. The first proposed installation
uses the full Hyper-V role, an optional component requiring elevated setup and
potentially a reboot;
Microsoft excludes Home from the full Hyper-V role. Its 4 GiB platform minimum is
not an Oblivion capacity recommendation. Our controller plus nested Safes needs
its own measured admission budget. [Installation](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/Install-Hyper-V),
[hardware requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements).

The HCS schema provides `ComputeTopology.Processor.ExposeVirtualizationExtensions`
as a boolean from version 2.0. `Chipset.LinuxKernelDirect` and `Devices.VirtioSerial`
are available from schema 2.2. Use the versioned controller kernel/initrd directly;
the initial backend therefore does not depend on VMMS Generation 2 ISO/EFI boot.
[HCS schema](https://learn.microsoft.com/en-us/virtualization/api/hcs/schemareference).

Microsoft's WSL implementation checks Windows 11 and the HCS processor capability
`NestedVirt` before enabling that flag. Its native helper obtains the capability
through `HcsGetServiceProperties`, with a `ProcessorCapabilities` query. Reuse
that detection pattern without creating a WSL distribution. A reported capability
still needs an actual Debian/KVM inner Safe boot. Windows ARM64, Home and other
editions remain outside the first proposed matrix; no GUI hypervisor or emulation
fallback is part of this path. [Microsoft capability check](https://github.com/microsoft/WSL/blob/master/src/windows/service/exe/WslCoreVm.cpp#L1472),
[HCS query](https://github.com/microsoft/WSL/blob/master/src/windows/common/hcs.cpp#L101).

```text
Windows Terminal / PowerShell -> oblivion.exe
  -> Oblivion-owned headless HCS / Hyper-V controller
       -> the same versioned Debian controller for amd64
            -> Safe Linux VMs + per-Safe gateways
```

The [HCS helper source](../packages/oblivion-native-windows/README.md) now creates
an owned compute system, provisions a private per-boot token and relays authenticated
local control pipes over AF_HYPERV. Its typed configuration can prepare one
owned network adapter, or omit networking entirely. `capabilities` reports observed HCS availability
separately from product support, which remains false. The common CLI has a
Windows transport adapter for this endpoint. The native Runtime supplies console
passwords, guest terminal frames, pipe I/O, resize, signals and opening-scoped
human activity to the common workflows. The command entrypoint now discovers the
registered installation and holds a supervisor lease while running these workflows
or the real manager child. Its terminal keeps the control lease until explicit agent release;
guest Exit alone must not race the controller's EOF cleanup.

In an interactive agent or shell, F7 opens Files and F9 opens Network for the
attached Safe. Esc returns to the guest. The launcher waits for its console
reader to stop before the panel takes input and continues draining the guest
stream while the panel is visible. The panel and its CLI children run in an
owned Windows job. Before restoring guest input, the launcher observes that
the job has emptied, restores the console modes and screen, and clears
queued input. The physical gesture and the installed Windows Terminal and
Hyper-V paths require on-device acceptance.

## Installed development entrypoint

The Windows `oblivion.exe` is built from `packages/oblivion-cli` with the explicit
`windows-launcher` build feature. Its top-level grammar and help have the same
owner as the Unix launcher. Official agent arguments remain opaque. Invalid
syntax and currently unavailable local endpoints fail before installation
discovery, private prompts or VM startup.

Produced Windows development bundles include `install.cmd`. Run it from a normal
terminal in the bundle directory; it invokes the same `runtime install-bundle`
operation. PowerShell 7, Python, Rust and the Windows SDK are builder dependencies,
not installer prerequisites. The native setup requests UAC only for its helper;
the terminal and any later manager remain unelevated. Starting setup as a normal
user also preserves that user's identity when UAC asks for another administrator's
credentials.

Before UAC, the caller verifies the source bundle and copies only its software
into a fresh pinned staging directory. Its owner and SYSTEM retain full access;
administrators receive read/execute access. No Safe data or provider profiles
enter this staging tree. The parent retains the exact process handle returned by
`ShellExecuteExW` and verifies the connected pipe server before sending. After a
bounded read, the helper authenticates the actual pipe caller's token against
the staging owner and reverts before privileged work. No SID or installation
target supplied in a message can select another user's installation.

Setup checks the actual Windows build, supported edition, hardware observations,
the Hyper-V feature state and HCS capabilities. If Hyper-V must be enabled, the
ordinary terminal requests explicit confirmation before the helper runs the fixed
System32 DISM operation. No PowerShell or ADK is required. A pending feature change
or restart result stops setup before an Oblivion VM, service or data disk is
created: restart Windows and rerun the same installer. Setup never restarts the
computer automatically or changes firmware, Secure Boot, VBS or unrelated VMs.

`runtime install-bundle DIRECTORY` verifies a current source-bound manifest,
the exact inventory, hashes, file identities and ACLs. It creates a private
`%PROGRAMDATA%\Oblivion\SID` root discovered with the Windows known-folder API,
rather than trusting an environment override. The durable Pending record precedes
publication, configuration and VHDX creation. It publishes into a new release
directory and prepares separate boot copies; HCS grants never modify the immutable
installed bundle's ACLs. The data VHDX remains outside replaceable software.

Setup boots the new controller, waits for authenticated control and stops it
cleanly. Only after checking the ungranted VHDX UUID, capacity and file identity
does it commit Ready. Encrypted user storage is created separately by `oblivion
init` or the manager. Pending setup has explicit Uncreated, Staged and Published
disk states. The installer creates a randomly named private VHDX, flushes it,
records its original FileID/UUID/capacity, then publishes it without replacing a
target. A rename completed before the next registry commit is reconciled only
by that same FileID. SDK-created but unrecorded staging files remain untouched;
a new attempt never adopts them as initialization authority.

Rerunning the exact bundle resumes Pending setup under one exclusive setup lock.
Software, configuration and boot copies publish atomically and complete verified
copies can be reused. Only the recorded disk can regain a bootstrap capability;
a matching filename or VHDX UUID alone is insufficient. Ready removes that
Pending authorization. No automatic deletion of partial or unknown data is
implemented.

If bootstrap committed Ready but SCM registration failed, rerunning installation
with the exact verified bundle completes registration under the stopped-runtime
guard. It never recreates the recorded data disk. During maintenance the
broker is Disabled before stopping it; the new ImagePath and demand-start mode
are committed together before the guard is released. An interrupted maintenance
operation can leave the broker disabled and requires retrying the matching
verified bundle, rather than bypassing that fence.

The privileged installation phase requires an elevated token and available
nested HCS capabilities before creating runtime data, then registers the protected
helper as the authenticated user's SCM service. The parent watches cancellation;
the helper observes caller EOF throughout feature servicing and installation and
joins its owned worker. The parent removes staging only after actual helper exit. A
cancelled DISM operation is not reported as a rollback; another attempt re-queries
Windows. Normal launch starts the service through limited SCM rights. Update,
collection and removal use the same authenticated UAC handoff from the ordinary
CLI; only their helper is elevated. The source bundle must
also meet the private ACL contract; arbitrary extraction into a broadly writable
directory is not accepted as a trusted installation source.

This native setup is source implementation, not an installed-Windows result.
Acceptance must include both same-account consent and a standard user entering a
different administrator's credentials, refusal of UAC/feature changes, caller loss
during servicing and resumption after reboot. Also test starting both PE files on
a clean Windows 11 Pro installation with Hyper-V disabled: the Windows SDK imports
ComputeCore/ComputeNetwork, and linking those APIs does not prove that the loader
can reach setup on that baseline. No DLL download or alternate VM path is used.

`oblivion` launches the real manager with its installed assets and launcher path,
keeping the verified bundle and runtime lease alive until the child exits.
`runtime start` explicitly makes the runtime resident. Status polls and activity
reports read only bounded private metadata and address existing control pipes;
they do not hash the ISO or boot a stopped runtime. Files browsing and guest
transfer status/recovery use private, opening-scoped messages. Local Files import
and export now use the same manifest, reviewed approval, payload protocol and
receiver journal as Unix. Personal-backup streams also use native file endpoints
and the shared restore workflow. Share also uses its common reviewed workflow.
Stopped-only update, software collection and uninstall are also connected. The
Live storage selector is unavailable on Windows.

## Stopped-only software maintenance

Close the Safes and run `oblivion runtime stop` first. The development CLI now
connects `runtime update BUNDLE`, `runtime gc` and `runtime uninstall` from a normal
terminal. An explicit update verifies the incoming current-format bundle and
binds the UAC exchange to that bundle's source, including when it differs from
the invoking CLI. GC and uninstall verify the actual running launcher's file
identity and role before staging. Only published-software ancestor pins use
metadata-only access; root/file ACLs, hashes and private data access are unchanged.
None of these maintenance operations boots
a VM or changes the data VHDX, runtime identity or configuration.

A Stopped journal alone is insufficient. Maintenance owns the runtime election
and the exclusive journal writer after the previous supervisor releases it.
That authority remains held through filesystem changes and prevents a concurrent
start. An update records its exact base and target, replaces only verified boot
files and commits the new binding. The recorded transition can finish after a
rebind without treating another bundle as a compatible substitute. Bundle and
boot-file copies publish from complete private staging; interrupted copies never
occupy the deterministic target name. Registry and supervision journal replacement
use flushed private files under their existing ownership locks.

`gc` removes only complete, verified obsolete software. Uninstall records removal
of the software before collection, retaining the installation record, `vm.json`,
supervision journal and exact `data.vhdx`. Unknown files and mapped/in-use binaries
remain untouched and appear in the cleanup report. Exit code 2 means removal is
incomplete; retry from a verified external bundle after closing installed programs.
The caller keeps its source bundle pinned through helper exit, so uninstall from
an installed CLI retains that complete in-use release rather than deleting part
of it. A verified external bundle can finish removal. Both reinstall through
`install.cmd` and `runtime update BUNDLE` restore software around the retained
data and identity; they never regain a new-disk initialization capability.
No data-purge or delete-at-reboot operation is introduced.

After authenticated installation or update, the original parent registers the
verified `releases/BUNDLE_ID/bin` directory in its own HKCU PATH. There is no
command wrapper and agent arguments go directly to the native executable.
Uninstall removes only the entry owned by that runtime, even if software cleanup
is incomplete. Other PATH entries, raw UTF-16 and REG_SZ/REG_EXPAND_SZ types stay
under the user's control. A bounded pending record precedes each write and
reconciles only known before/after snapshots; unknown registrations, collisions
or unrelated changes are preserved and reported. A registration failure returns
code 2 without reporting that the completed software operation was rolled back.
Windows receives an environment-change notification, but the calling terminal's
inherited PATH cannot be changed: open a new terminal after installation/update.

`runtime recover` refuses a healthy supervisor that still owns its journal.
A live supervisor already stopping can retry its authenticated stop. If the
writer is gone, recovery first acquires the exclusive journal writer and the
backend's lifetime resource lock. It records Recovery before external work and
records Stopped only after the following checks complete.

The private resource receipt binds source/configuration, client/storage SIDs,
runtime/generation, the original four file identities and virtual disk capacity,
and the exact HCN plan. It is flushed, atomically published and read back before
HCN creation, VM grants or HCS creation. HCS Owner and HCN names include that
same generation. Reconciliation stops only the matching VM, verifies actual
Stopped or scoped absence, validates both HCN objects before deleting either,
and revokes access only on the receipt's original files. Changed identities,
foreign properties and unknown permissions preserve Recovery; no arbitrary
resource adoption or ACL rewrite is performed.

Without a receipt, recovery performs no external mutation: it requires positive
HCS absence, both HCN IDs absent and strict ungranted runtime files with the
correct VHDX identity. A missing pipe or file is not sufficient evidence. A
helper still finishing cleanup retains the resource lock and prevents recovery
from racing its operations. Pending setup can cancel only its previous owned
initialization process, wait for observed process exit and reconcile its receipt
before resuming. This internal action is unavailable for an ordinary Existing
runtime and never treats a killed helper as proof of VM shutdown. A clean receipt
is rechecked against strict original-file evidence without repeating an already
completed ACL revoke. Filesystem, mutex, receipt replacement and SDK fixtures compile
for Windows but have not been executed here. Forced interruption, power loss,
HcsRevokeVmAccess with an already-absent ACE and installed lifecycle remain
acceptance gates.

## Local Files copies

`files import --safe GB --source .\project` and `files export --safe GB --path
workspace/project --destination .\output` now connect the Windows filesystem
endpoints to the installed CLI. Repeated selectors use one named collection.
The console shows the prepared manifest before confirmation; unattended copies
require `--yes`. The manager uses the shared `--events` approval flow, whose
cancel/EOF revokes hashing and copy I/O. Import never contacts the guest receiver
before approval. Export pins the selected local destination before review and
creates its private staging only after approval.

Local paths must resolve to a local drive. Component-by-component handle access
rejects reparse points and hard links; files stay pinned through review and
streaming. The receiver checks Windows reserved names, alternate streams,
trailing-dot/space aliases and case-insensitive collisions before review instead
of renaming them silently. Publication never replaces an existing destination.
Windows recovery records bind volume GUID, volume serial and 128-bit file ID;
Unix uses its own filesystem identity in the same current-format record.
No beta-format reader or host path is added to the manifest/event channel.

The copy owns a quiet pipe lease independently of its cancellable data stream.
It releases the exact controller client before dropping that lease, even after
I/O cancellation. A missing final receipt, release error or lost output is an
interrupted/uncertain outcome to inspect, not permission to repeat the copy.
`files transfers/status/recover/discard --destination DIRECTORY` reuse the same
receiver inventory and journal without creating records during inspection.

Native filesystem, named-pipe, consent and actual copy-orchestration fixtures
are registered in Windows CI. Local MSVC compilation on the Mac is not evidence
that they passed on Windows, that directory synchronization works on every
filesystem, or that an installed Hyper-V transfer has been qualified.

## Personal backup streams

Personal backups now connect `backup export/import` to the installed Windows
entrypoint. The common workflow checks writable storage, a closed persistent
Safe, the fixed maintenance slot, preparation metadata and exact copy receipts.
Only the selected ciphertext file is streamed; password validation and restore
remain inside the controller. Backup data-channel EOF ends its authority, then
controller status must confirm Copied before output publication or restore.
This is distinct from the explicit AgentRelease used by Files. Native file
authority stays pinned through review/copy/publication, without adding a new
UUID requirement to Unix raw-backup destinations. The Windows execution and
installed backup/restore acceptance gates remain open.

## Share streams

The installed Windows entrypoint now accepts the shared Share grammar and
executes the same export/import/status/discard engine as Unix. Container format,
source review, credential exclusions, fresh destination mapping and final
authentication are unchanged. The desktop only reads the explicitly selected
ciphertext input and writes a private ciphertext output. Source and import
streams stay bound to their captured Safe opening, slot and native client.

The export signal is an independent authority: EOF or revocation interrupts
pending source I/O through bounded native wait slices. Dropping its owner also
revokes watchers that still hold references. Core acknowledges ShareRelease,
ShareImportFinish or ShareExportEnd before closing the corresponding native
lease; cleanup uses a fresh authenticated cancellation scope. No AgentRelease
substitution, detached worker or direct-network fallback is introduced.

Real Unix stream tests cover the two export reviews, receipt and cleanup before
publication, changed-plan refusal and import receipt failure. Windows named-pipe
fixtures are compiled for MSVC, not executed here. Neither this source increment
nor successful Linux controller compilation qualifies installed Windows Share
or transfer between two actual installations.

The executable smoke tests exercise help, version and pre-startup rejection on
Windows without starting a VM. The actual installed lifecycle and HCS permissions
remain hardware acceptance gates, regardless of cross-compilation results.
The [development builder](DESKTOP.md#build) creates the real CLI/helper PE files
and manager assets, and assembles a bundle only with a matching real runtime.
No-runtime output is labelled build inputs and cannot be installed as a bundle.

The helper pins trusted boot assets, a private VHDX and their parent directories,
checks actual ACLs and file identities, and grants VM access only to that reviewed
set. The new installation contract binds the VHDX Identifier to the runtime UUID;
the guest separately verifies the virtual disk's runtime marker or filesystem
UUID. Configuring a VHDX container is not sufficient to initialize that content.
Supervisor EOF revokes the helper, including during bounded HCS waits. A successful
HCS request is not a stopped observation. Unknown cleanup retains leases until the
one-shot process exits. Explicit recovery uses the protected generation receipt
and original file identities; the actual SDK cleanup remains a qualification gate.

## Owned controller network

An isolated ICS network follows Microsoft's WSL HCN path. A separate manual
WinNAT network is unsuitable: Microsoft documents a single internal NAT prefix
and warns of unknown state with multiple independent NATs. The helper instead
creates its own named ICS switch and endpoint; it never adopts another product's
network. The same default HCN schema is used for creation and queries, with no
second version reader or fallback path. Requested static addresses must be
confirmed by the provider. Existing host routes and HCN subnets constrain the
private `/28` selection. [WinNAT limits](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/setup-nat-network),
[WSL creation and observation](https://github.com/microsoft/WSL/blob/master/src/windows/common/NatNetworking.cpp),
[default schema](https://github.com/microsoft/WSL/blob/master/src/shared/inc/hns_schema.h).

DHCP is not assumed. The HCS builder appends only validated IPv4, gateway and MAC
metadata. A controller-only service writes a private NetworkManager keyfile in
`/run` before NetworkManager starts. It matches the actual NIC by MAC and uses
static IPv4; automatic DHCP profiles are disabled for the Hyper-V adapter. The
existing empty resolver, firewall and IPv6 restrictions remain unchanged.
Per-Safe traffic still traverses the inner gateways and their Tor/SOCKS5 policy.

The requested flags enable nonpersistent networking without requesting DNS or
DHCP service. WSL normally includes the DNS flag: our exact flag combination,
SharedAccess behavior and coexistence remain Windows acceptance gates. HCN calls
are synchronous and expose no cancellation handle. Creation occurs before HCS VM
creation, and deletion only after Stopped is observed. A blocked service call is
not turned into a fabricated deadline or a detached mutating worker. Cleanup
checks both resource identity and observed absence; failed cleanup requires
reconciliation through the protected generation receipt; actual HCN behavior
still requires Windows qualification.

The source installer connects feature detection, explicit elevation, image
verification, VM preparation and a restart-required outcome. The ordinary-user
broker controls only its registered VM/disk identities. Actual Windows execution
must qualify that boundary; source and cross-compilation are insufficient.

## Why WSL2 is not an interchangeable fallback

WSL documents a Windows 11 `nestedVirtualization` setting, default enabled. The
current Microsoft x86 kernel source enables modular KVM for Intel and AMD.
Neither fact proves that the installed kernel/modules and CPU can run our inner
Safe. Both `/dev/kvm` capability checks and a real nested boot are still required.
[WSL settings](https://learn.microsoft.com/en-us/windows/wsl/wsl-config),
[Microsoft kernel configuration](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.y/arch/x86/configs/config-wsl).

A WSL distribution normally enables Windows-drive mounts and Windows-process
interop. VM kernel/memory/swap settings are global across WSL distributions, while
other settings are per distribution. It would need a separate image/boot and
isolation contract, audited mounts, interop, swap and crash settings; modifying
`.wslconfig` could affect the user's existing distributions. Running our current
controller inside an ordinary WSL distribution is consequently not equivalent
to booting the dedicated immutable controller image. Keep WSL2 as a separately
reviewed option, rather than silently selecting it on Home or after Hyper-V
failure. [Configuration scopes and defaults](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).

## Guest and transport work actually missing

Hyper-V provides local stream sockets: `AF_HYPERV` on Windows and `AF_VSOCK` in
Linux, addressed using VMID plus a service GUID. Microsoft describes the Linux
service-GUID-to-port template and requires `CONFIG_HYPERV_VSOCKETS`. This is a
suitable candidate for the existing controller relay on port 4050, without a LAN
control listener. The HCS backend must configure its owned VM's services; retain the
per-boot authentication and opening nonces, since a transport address alone is
not application authorization. [Hyper-V sockets](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service).

HCS exposes per-service host bind/connect security descriptors under
`Devices.HvSocket.HvSocketConfig.ServiceTable`. Configure explicit broker access
and avoid wildcard binds. This documented HCS configuration must not be assumed
to apply to a VM created through the separate VMMS management interface.
[Socket configuration](https://learn.microsoft.com/en-us/virtualization/api/hcs/schemareference#hvsocketserviceconfig).

### Per-boot authentication: private VirtioSerial

The implemented bootstrap keeps guest `READY`, a fresh 32-byte host token, then
guest `SET`. `host/runtime-auth.py` now accepts `hcs-hyperv` alongside `apple-vz`
and `qemu-kvm`; HCS and QEMU use the same authenticated protocol implementation.
The token stays
in broker memory and the guest's private `/run` directory, never argv, the HCS
configuration, KVP or a plaintext host file.

Microsoft's implementation provides a concrete transport pattern. Its
`DmesgCollector` creates a host named-pipe server before VM creation; the VM
configuration then connects a VirtioSerial port to that pipe. Use a dedicated
non-console port named `oblivion.runtime-auth`, not a debug console or log relay.
[Host pipe creation](https://github.com/microsoft/WSL/blob/master/src/windows/common/Dmesg.cpp#L49),
[creation order](https://github.com/microsoft/WSL/blob/master/src/windows/service/exe/WslCoreVm.cpp#L283),
[port configuration](https://github.com/microsoft/WSL/blob/master/src/windows/service/exe/WslCoreVm.cpp#L1539).

Create the pipe with an explicit restrictive DACL before handing its name to HCS,
one instance, `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`.
The authentication port has `ConsoleSupport: false` explicitly and no kernel
`console=` parameter. It is a named serial port, never the kernel's `hvc0`
console; console output must not share the READY/token stream. Microsoft's WSL
configuration enables `ConsoleSupport` for its separate `hvc0` port.
Windows documents these controls; default pipe security is unsuitable because it
also permits Everyone/anonymous reads. The exact HCS connecting identity and
its access under the proposed DACL still require qualification on Windows.
Do not silently broaden permissions if it fails. `HcsGrantVmAccess` is documented
for files, so it is not evidence of a named-pipe permission solution.
[Pipe API](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew),
[pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights),
[VM file access](https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcsgrantvmaccess).

KVP is excluded from secret provisioning: Linux stores its pools in
`/var/lib/hyperv/.kvp_pool_*`. HCS configuration must also contain no token or
credentials; Microsoft's wrapper demonstrates that configuration JSON can enter
diagnostic logs. No public-key bootstrap or new cryptographic protocol is needed
for the proposed private serial path. [KVP storage](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/integration-services-data-exchange),
[configuration logging](https://github.com/microsoft/WSL/blob/master/src/windows/common/hcs.cpp#L81).

### Controller image and remaining integration

Driver groundwork is implemented in the shared controller build sources. On
amd64, kernel selection now requires Hyper-V VMBus, synthetic SCSI storage,
disk/CD-ROM, networking and vsock support, either built in or present as actual
modules. The controller explicitly adds modular drivers to its initramfs while
retaining VirtIO. Packing checks the finished archive for every required module
from the selected ABI; `hypervisor-kernel.json` records driver modes, module
checksums and the initramfs checksum. ARM64 is unchanged by this Windows x64
contract. The checks use the upstream names, including `hv_vmbus`, `hv_storvsc`,
`hv_netvsc` and `hv_sock`.
The inventory also requires `virtio_console` for the named bootstrap port and
`virtio_mmio`, enabled by the reference Microsoft kernel. Modular dependencies
are included by initramfs-tools; no hard-coded MMIO address or extra kernel
transport argument is introduced.
[VMBus](https://github.com/torvalds/linux/blob/v6.12/drivers/hv/Makefile),
[storage](https://github.com/torvalds/linux/blob/v6.12/drivers/scsi/Makefile),
[network](https://github.com/torvalds/linux/blob/v6.12/drivers/net/hyperv/Makefile),
[vsock](https://github.com/torvalds/linux/blob/v6.12/net/vmw_vsock/Kconfig).
[Reference Microsoft kernel](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.y/arch/x86/configs/config-wsl).

Focused source fixtures cover built-in/module configurations, missing or changed
drivers and a small Debian initramfs archive. No controller image or Hyper-V VM
has been built or booted to qualify this increment. Driver coverage introduces
no Hyper-V runtime backend, authentication alternative or firmware policy.

Concrete integration and qualification still required:

- Package and qualify the HCS direct-kernel/initrd boot, supported schema and
  nested processor capability. Neither the Linux helper nor driver fixtures
  establish a Windows boot or an accelerated inner Safe.
- Qualify the implemented guest disk selector: it binds the configured VMBus
  controller GUID, storage class/driver and data LUN before marker/UUID checks,
  rather than trusting an `sdX` name. Current fixtures use actual temporary sysfs
  trees; they do not prove Hyper-V's presentation on the target Windows host.
- Qualify the HCS-owned pipe/provisioner above, its compute-system lifetime,
  connecting peer/DACL and guest port identity.
  An unsuccessful handshake must prevent control access; no SSH, shared host
  folder, unauthenticated TCP or weaker fallback is part of this bootstrap.
- Integrate the implemented local Windows IPC with the Windows frontend and
  installer. It uses explicit per-user/broker ACLs and verified client identity.
  Named-pipe defaults can grant read access to Everyone and
  anonymous users, so default ACLs are unsuitable here. [Pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

## Storage and lifecycle

Fresh-disk creation is now implemented with `CreateVirtualDisk`, a private owner
and DACL, pinned ancestors and the runtime UUID. The initial-install helper owns
the resulting creation capability through first boot. Its private bootstrap
sends the runtime identity and capacity; the guest places this authority in
root-only RAM and consumes it before marking the matching blank block device.
It then uses the existing ext4 preparation. Ordinary `run` sends Existing and
refuses a blank, unrecognized disk. This does not require attaching the VHDX to
the Windows host for formatting. Pending setup recovery is connected in source;
actual installation and forced-interruption behavior remain to be qualified. [SDK creation](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-createvirtualdisk).

A VHDX can present the same logical block disk to the controller; LUKS2 and Safe
volumes remain inside it, with no Windows filesystem mount. Microsoft supports
fixed and dynamically allocated virtual disks. Choose allocation only after
space/admission and growth tests; a VHDX wrapper is not encryption. Bind the
installation to its VM GUID, VHD identity and verified filesystem object, not
merely a mutable pathname. Reject unrelated, replaced or reparse-point objects.
[New-VHD](https://learn.microsoft.com/en-us/powershell/module/hyper-v/new-vhd?view=windowsserver2025-ps),
[Get-VHD](https://learn.microsoft.com/en-us/powershell/module/hyper-v/get-vhd?view=windowsserver2025-ps).

Use verified guest shutdown, explicit failed-shutdown recovery and actual HCS VM
state. Do not interpret a helper PID disappearing as the VM stopping. HCS compute
systems are ephemeral and must be recreated after stopping; configure
`ShouldTerminateOnLastHandleClosed` and keep the owning handle under the runtime
lifetime contract. Do not use saved-memory stop, save/restore or checkpoints as
the normal shutdown mechanism. [HCS lifecycle](https://learn.microsoft.com/en-us/virtualization/api/hcs/overview),
[handle lifetime](https://learn.microsoft.com/en-us/virtualization/api/hcs/schemareference#computesystem).
A crashed or privileged Windows host may still capture RAM in pagefiles, dumps
or external snapshots. This remains a desktop trust boundary, not a guarantee
of an air gap or of zero plaintext managed by Windows itself.

## One CLI implementation, platform adapters

`oblivion-cli` owns the top-level grammar and shared orchestration for agent
launch, storage, Safe administration, network/proxy commands, tasks, family
passwords, backup recovery and Files metadata. Both actual executables consume
that code. `oblivion-wire` owns private controller/agent framing and DTOs;
`oblivion-transfer` owns copy consent, manifests, receipts and receiver outcomes.
Linux controller services remain in the Linux package, rather than being linked
into each desktop executable.

Windows adapters supply the console, private named pipes, filesystem handles,
installation discovery and supervised HCS runtime. Files import/export uses
these concrete authorities and the shared exchange. Agent arguments remain
opaque arrays; no PowerShell command string is constructed. The three official
agent binaries remain the pinned Linux binaries inside each Safe.

The manager target descriptor selects `oblivion-manager.exe`, `oblivion.exe`
and the pinned OpenTUI x64 DLL. It is shared by the builder and installed
launcher discovery. Local pickers receive native parent paths; guest pickers
retain POSIX paths. The source-bound bundle validator supports Windows assets
without depending on Unix ownership APIs. Compilation and fixture definitions
do not qualify the installed manager or Hyper-V path.

Remaining work includes installed broker/recovery qualification and real setup
interruption across SDK creation, publication and guest preparation. Foreign
resources are never adopted by recovery. The full
installed path must then pass the acceptance gates below. There is no second
Windows command grammar, beta compatibility reader or automatic emulation fallback.

For a launcher attached to an existing Windows Terminal, use its console/VT
interface and forward the guest PTY. Raw keyboard input requires explicit console
mode handling; resize events are not returned by ordinary `ReadFile`. Pipe mode
must bypass console transformations and preserve separate byte-exact stdout and
stderr. [Console modes](https://learn.microsoft.com/en-us/windows/console/setconsolemode).
ConPTY is the API for hosting a **local Windows console process**; it is not
required merely to display the remote Linux TUI. If a local manager/child host
needs it, use separate pipe-draining workers and `ResizePseudoConsole` rather
than blocking both directions on one thread. [Pseudoconsole lifecycle](https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session).

## Order and evidence before support

First complete the portable boundary and run Windows CI against framing, argv,
UTF-8, pipe separation, ACL/reparse rejection and terminal restoration. Then, on
a real Windows 11 x64 machine, automate one controller boot, authenticated
transport and one inner Safe boot with hardware acceleration. Continue with a
real native conversation, Files, lock/crash/reboot/resume, two Safes with isolated
Tor/SOCKS5 failures, teardown and retained encrypted data after reinstall.
Finally qualify ordinary-user install/update/uninstall, clipboard controls,
mouse/resize, memory and disk measurements, and inspect synthetic canaries in
managed logs, dumps, VM files and staging. A green cross-build or a successful
Hyper-V outer boot proves neither nested KVM nor these acceptance requirements.
