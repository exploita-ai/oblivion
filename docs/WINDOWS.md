# Windows native backend — feasibility and implementation proposal

Implementation checkpoint: 5 November 2026. **The Windows product is not complete
or qualified.** An experimental HCS helper core and owned HCN ICS network are
implemented. A same-user authenticated named-pipe client and shared CLI adapter
are now present. The installed command entrypoint, bundle verification and
one-shot per-user setup and local Files payload endpoints are connected in source;
ordinary-user admission now uses a demand-start SCM broker in source, while
unknown-resource reconciliation and installed privilege qualification remain open.
Stopped-only update, software collection and uninstall are now connected in source.
The manager has a Windows x64 build target; its PE
execution and complete installed path still need qualification. This is a proposal for phase 8 of the
[roadmap](oblivion1.0-roadmap.md), rather than instructions for an available product.
No Windows VM has been booted to qualify this source increment.

The source supervisor now elects one private runtime generation and gives each
terminal a lease. It owns the helper process and lifetime pipe; control probes
verify that exact kernel process object, not merely an SID or recorded PID.
The last lease requests guarded shutdown, and only a confirmed helper exit after
HCS/network/grant cleanup permits Stopped. Failed or uncertain shutdown persists
Recovery. Recovery after losing the supervisor still needs the dedicated owned
resource reconciliation; an absent pipe cannot clear that fence.

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

## Installed development entrypoint

The Windows `oblivion.exe` is built from `packages/oblivion-cli` with the explicit
`windows-launcher` build feature. Its top-level grammar and help have the same
owner as the Unix launcher. Official agent arguments remain opaque. Invalid
syntax and currently unavailable local endpoints fail before installation
discovery, private prompts or VM startup.

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
init` or the manager. A failed or interrupted setup remains Pending and cannot
be retried as a new disk initialization. No automatic deletion of partial or
unknown content is implemented.

If bootstrap committed Ready but SCM registration failed, rerunning installation
with the exact verified bundle completes registration under the stopped-runtime
guard. It never creates or initializes another disk. During maintenance the
broker is Disabled before stopping it; the new ImagePath and demand-start mode
are committed together before the guard is released. An interrupted maintenance
operation can leave the broker disabled and requires retrying the matching
verified bundle, rather than bypassing that fence.

Setup requires an elevated token and available nested HCS capabilities before
creating files, then registers the protected helper as the user's SCM service.
Normal launch starts that service through limited SCM rights; no terminal or
manager elevation is requested. Setup/update/removal do not elevate implicitly.
The source bundle must
also meet the private ACL contract; arbitrary extraction into a broadly writable
directory is not accepted as a trusted installation source.

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
connects `runtime update BUNDLE`, `runtime gc` and `runtime uninstall`. When
changing source versions, run the new verified bundle's launcher so its source
binding matches the incoming bundle. None of these maintenance operations boots
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
Reinstall through `runtime update BUNDLE` preserves the retained data and identity.
No data-purge or delete-at-reboot operation is introduced.

`runtime recover` retries a guarded stop only in stop/recovery states, using the
authenticated live supervisor and then requiring the same Stopped proof. It
refuses a healthy active runtime with an instruction to use `runtime stop`. An
absent supervisor, unknown HCS/HCN resources or uncertain ACL grants remain fenced;
this is not orphan-resource adoption or complete crash recovery. Filesystem,
mutex, pipe and replacement fixtures are compiled for Windows, not executed on
this Mac. Power-loss durability and installed lifecycle remain acceptance gates.

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
one-shot process exits and requires explicit grant reconciliation; that recovery
frontend is still to be implemented.

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
reconciliation by the unfinished recovery frontend.

The installer should automate feature detection, explicit elevation, VM creation,
image verification and any restart handoff. Everyday commands should run as the
normal user. Prefer a narrowly scoped privileged backend controlling only its
registered VM/disk identities over requiring every user to become a Hyper-V
administrator. This permission model is a proposed implementation requirement,
not a capability proved by the existing code. No installer should silently
change host Secure Boot, VBS, unrelated VMs or their networks.

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
the Windows host for formatting. Installed setup and interrupted-install recovery
remain to be connected and qualified. [SDK creation](https://learn.microsoft.com/en-us/windows/win32/api/virtdisk/nf-virtdisk-createvirtualdisk).

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

Remaining work includes installed broker qualification and explicit reconciliation of owned HCS,
network and ACL grants after uncertain shutdown or interrupted setup. The full
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
