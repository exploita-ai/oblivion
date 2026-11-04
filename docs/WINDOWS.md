# Windows native backend — feasibility and implementation proposal

Research checkpoint: 4 November 2026. **The Windows backend, installer and manager
bundle are not implemented or qualified.** This is a proposal for phase 8 of the
[roadmap](oblivion1.0-roadmap.md), rather than instructions for an available product.
No VM or Windows configuration was changed during this audit.

## First target: Windows 11 x64 with explicit Hyper-V

Start with Windows 11 Pro/Enterprise, Intel VT-x/EPT or AMD Ryzen/EPYC, firmware
virtualization enabled, and a Generation 2 Hyper-V controller VM. The role is an
optional Windows component requiring an elevated setup and potentially a reboot;
Microsoft excludes Home from the full Hyper-V role. Its 4 GiB platform minimum is
not an Oblivion capacity recommendation. Our controller plus nested Safes needs
its own measured admission budget. [Installation](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/Install-Hyper-V),
[hardware requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements).

Enable `ExposeVirtualizationExtensions` on the stopped, owned controller VM.
Microsoft lists Intel VM configuration version 8.0+ and AMD version 9.3+, with
Windows 11 or Server 2022+ for AMD. These documents establish a mechanism for
exposing CPU extensions; they do not qualify our Debian/KVM nested workload.
A successful outer boot must therefore be followed by an actual inner KVM boot,
not merely a CPU-feature check. Windows ARM64, Home and other editions remain
outside this first proposed matrix. No UTM/VirtualBox window or software-emulation
fallback is part of this path. [Nested virtualization](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization).

```text
Windows Terminal / PowerShell -> oblivion.exe
  -> owned headless Hyper-V Generation 2 controller
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
control listener. Socket registration requires administrative setup; retain the
per-boot authentication and opening nonces, since a transport address alone is
not application authorization. [Hyper-V sockets](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service).

Concrete changes required by our source:

- Add Hyper-V VMBus, storage, network and vsock driver coverage to the **same**
  controller kernel/initrd. Current explicit initramfs modules assume VirtIO.
- Qualify Generation 2 EFI boot and its VM-local Secure Boot policy. The present
  bundle's direct-kernel paths do not prove the ISO boots in Hyper-V firmware.
- Replace assumptions about VirtIO block names with validated runtime disk
  identity; Hyper-V synthetic SCSI devices use a different presentation.
- Implement a Hyper-V boot-auth provisioner. `host/runtime-auth.py` currently
  recognizes only `apple-vz`/`qemu-kvm` and uses a private VirtIO serial port for
  the Linux token. Hyper-V does not supply that device. Choose a versioned,
  VMID-bound bootstrap through the native backend; do not bypass authentication
  or introduce SSH, a shared host folder or unauthenticated TCP.
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

Use verified guest shutdown, explicit failed-shutdown recovery and actual VM
state. Do not interpret a helper PID disappearing as the Hyper-V VM stopping.
Disable automatic checkpoints and avoid a saved-memory stop policy for the
owned VM; Windows exposes both checkpoint and automatic-stop controls.
[VM settings](https://learn.microsoft.com/en-us/powershell/module/hyper-v/set-vm?view=windowsserver2025-ps),
[checkpoints](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/checkpoints).
A crashed or privileged Windows host may still capture RAM in pagefiles, dumps
or external snapshots. This remains a desktop trust boundary, not a guarantee
of an air gap or of zero plaintext managed by Windows itself.

## One CLI implementation, platform adapters

The existing CLI cannot simply cross-compile by adding a Hyper-V executable.
`launcher.rs` imports Unix process/FD APIs and uses POSIX signals and termios;
`channel.rs`/`remote_control.rs` require Unix sockets; `native_runtime.rs` and
`desktop_bundle.rs` depend on Unix filesystem ownership and locks. The transfer
crate mixes portable manifests/framing with Unix filesystem operations. The
manager builder and bundle platform table also omit Windows.

Proposed split, without a second command implementation:

1. Move the existing frontend commands/orchestration into a portable launcher
   boundary. Keep Linux controller services and storage code in the Linux host
   package, rather than linking them into every desktop executable.
2. Reuse one versioned wire model and frame encoder/decoder for control, agent
   argv, stdout/stderr, resize, Files, backup and Share. Separate the transfer
   manifest/validation code from its OS filesystem endpoints. No protocol alias
   or compatibility reader is needed for the unshipped 1.0.
3. Supply concrete terminal, private IPC, filesystem-identity and runtime-backend
   adapters for Unix and Windows. Preserve opaque argument arrays; never feed
   agent arguments into a PowerShell command string. The three agent binaries
   remain the existing pinned Linux binaries inside the Safe.
4. Add a Windows backend/installer using Hyper-V management APIs and the same
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
