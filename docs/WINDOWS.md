# Windows native backend — feasibility and implementation proposal

Research checkpoint: 4 November 2026. **The Windows backend and installer are not
implemented or qualified.** The manager has a Windows x64 build target; its PE
execution and complete installed path still need qualification. This is a proposal for phase 8 of the
[roadmap](oblivion1.0-roadmap.md), rather than instructions for an available product.
No VM or Windows configuration was changed during this audit.

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

Keep the existing bootstrap: guest `READY`, a fresh 32-byte host token, then guest
`SET`. `host/runtime-auth.py` currently accepts only `apple-vz` and `qemu-kvm`;
an HCS profile and backend provisioner remain to be implemented. The token stays
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
[VMBus](https://github.com/torvalds/linux/blob/v6.12/drivers/hv/Makefile),
[storage](https://github.com/torvalds/linux/blob/v6.12/drivers/scsi/Makefile),
[network](https://github.com/torvalds/linux/blob/v6.12/drivers/net/hyperv/Makefile),
[vsock](https://github.com/torvalds/linux/blob/v6.12/net/vmw_vsock/Kconfig).

Focused source fixtures cover built-in/module configurations, missing or changed
drivers and a small Debian initramfs archive. No controller image or Hyper-V VM
has been built or booted to qualify this increment. Driver coverage introduces
no Hyper-V runtime backend, authentication alternative or firmware policy.

Concrete changes still required by our source:

- Package and qualify the HCS direct-kernel/initrd boot, supported schema and
  nested processor capability. Neither the Linux helper nor driver fixtures
  establish a Windows boot or an accelerated inner Safe.
- Replace assumptions about VirtIO block names with validated runtime disk
  identity; Hyper-V synthetic SCSI devices use a different presentation.
- Implement the HCS-owned pipe/provisioner above, bind its lifetime to the owned
  compute-system identity, and qualify the pipe peer/DACL and guest port identity.
  An unsuccessful handshake must prevent control access; no SSH, shared host
  folder, unauthenticated TCP or weaker fallback is part of this bootstrap.
- Implement local Windows IPC with explicit per-user/broker ACLs and verified
  client identity. Named-pipe defaults can grant read access to Everyone and
  anonymous users, so default ACLs are unsuitable here. [Pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

## Storage and lifecycle

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

The existing CLI cannot simply cross-compile by adding a Hyper-V executable.
`launcher.rs` imports Unix process/FD APIs and uses POSIX signals and termios;
`channel.rs`/`remote_control.rs` require Unix sockets; `native_runtime.rs` and
`desktop_bundle.rs` depend on Unix filesystem ownership and locks. The desktop
bundle platform table still omits Windows.

The manager builder now uses a target descriptor shared with launcher discovery.
It selects `oblivion-manager.exe`, the sibling `oblivion.exe`, and the pinned
OpenTUI Windows x64 DLL, while retaining the same manager entrypoint. The default
target follows the actual builder host. The file picker receives an explicit
parent path from its local/native or guest/POSIX caller, so it no longer rewrites
Windows drive and UNC paths as guest paths. CI includes Windows target/picker
fixtures and compilation of the frontend/DLL. These sources and test definitions
do not establish an installed Windows runtime or a working Hyper-V backend.

The first shared boundaries are implemented and consumed by the existing
launcher. `oblivion-cli` owns one run-option and proxy grammar, preserving opaque
native arguments and returning a typed private-password request without doing
terminal I/O. `oblivion-wire` owns bounded private controller/agent framing.
`oblivion-transfer` separates manifests, payload verification, directory metadata,
copy messages and Share selection rules from Unix filesystem endpoints. All
three portable libraries compile for the Windows MSVC target; CI runs their
portable tests on Windows. This does not provide a complete Windows launcher, trusted
file handle implementation, ACL checks or a Hyper-V backend.

The actual `status --json`, `safes` and `close NAME` frontend is now shared in
`oblivion-cli`: one controller-state projection, Safe lookup, command parser and
executor. The existing Unix launcher calls it through its authenticated adapter.
Both Unix control paths consume the shared wire codec, retaining their distinct
local/native framing, deadlines and attachment ownership. The shared code
preserves raw JSON status and binds close requests to the observed slot and Safe
ID. This is a migrated frontend slice, rather than a second Windows command
implementation; the remaining orchestration and OS adapters are still open.

Agent `run`, storage lifecycle and tmux `shell --safe` now share their actual orchestration
as well. Safe lookup, creation/reopening, mode checks, protected startup and idle
cleanup use an injected controller and platform hooks; the existing Unix launcher
consumes them directly. Private terminal prompts, confirmation, clock/wait,
notifications and agent/Workspace attachment remain platform hooks. Run and shell
syntax is checked before VM startup. Transport, policy and cleanup calls after an
opening carry both the chosen slot and expected Safe ID. The portable code uses
the same network-command DTOs as the Linux controller, without linking to its
Unix services. Real Unix-socket fixtures cover the path; this is not a native
Windows terminal adapter or Hyper-V implementation.

Archive Init/Unlock/Ephemeral/Lock and network/proxy commands now have one shared
parser and executor too. First-run setup calls the same Init and Unlock rather
than an OS-specific initializer. The Unix adapter supplies only private entry and
confirmation. The network frontend keeps every Safe mutation and final status
bound to its observed slot/ID; saved proxy listing decodes bounded public metadata.
Malformed command arguments are rejected before VM startup or password entry. These source
paths and Unix-socket fixtures do not implement the Windows OS adapters below.

Remaining split, without a second command implementation:

1. Move the remaining command orchestration, including Files, family passwords,
   saved tasks, Share and backup, into the portable frontend boundary.
   Keep Linux controller services and storage code in the Linux host package,
   rather than linking them into every desktop executable.
2. Connect the shared CLI, wire and transfer boundaries to Windows transports
   and filesystem endpoints. Keep one command grammar and protocol rather than
   adding platform-specific copies or compatibility readers.
3. Supply concrete terminal, private IPC, filesystem-identity and runtime-backend
   adapters for Unix and Windows. Preserve opaque argument arrays; never feed
   agent arguments into a PowerShell command string. The three agent binaries
   remain the existing pinned Linux binaries inside the Safe.
4. Add a Windows backend/installer using HCS and the same
   runtime lifetime/lease contract. Compile and qualify a native OpenTUI manager
   artifact as well; a CLI-only substitute would not satisfy bare `oblivion`.

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
