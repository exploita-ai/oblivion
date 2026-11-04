# Windows HCS helper

Experimental `oblivion-vm.exe` source for a headless, owned Hyper-V controller.
This is the backend core, **not an installable Windows Oblivion release**.
The Windows frontend, privileged installation, VHDX initialization, network
recovery integration and actual nested-Safe boot remain unfinished or unqualified.
The surrounding architecture is described in [Windows](../../docs/WINDOWS.md).

The helper uses the Windows SDK through the pinned `windows-sys` bindings.
It creates only its own HCS compute system, requests nested CPU extensions and
direct kernel/initrd boot, and attaches one read-only ISO and one private VHDX.
There is no GUI, WSL distribution, host filesystem export, unauthenticated TCP
control listener or software-emulation fallback. `network: false` attaches no
network device. `network: true` prepares a separate, owned HCN ICS network and
one statically addressed controller endpoint before creating the VM.
`capabilities` distinguishes observed HCS/nested availability from product
support, which remains false until the complete integration is qualified.

The network follows the HCN default schema used by Microsoft's WSL implementation:
ICS with `IsolateSwitch: true` and the nonpersistent flag, a requested private
subnet and a separately owned endpoint. It does not adopt the Default Switch or
create a second manual WinNAT configuration. Host routes and existing HCN address
spaces exclude overlapping ranges. Returned identities, MAC, subnet and gateway
must match the request; a different assignment fails the run. Only validated
address metadata is appended to the kernel command line. Debian publishes a
private NetworkManager keyfile under `/run`, matches the NIC by MAC and uses
static IPv4. Auto-generated wired profiles are disabled for `hv_netvsc`; the
controller's existing resolver and IPv6 restrictions remain in place.
[Microsoft's HCN network path](https://github.com/microsoft/WSL/blob/master/src/windows/common/NatNetworking.cpp).

HCN service calls are synchronous and have no documented cancellation handle.
Lifetime checks surround the calls; creation precedes any VM and deletion follows
a confirmed stop. No timeout worker continues to mutate networking after the
helper reports a successful cancellation. A stalled HCN service, actual ICS with
the DNS flag omitted, interaction with other virtualization products and retained
resource recovery still need Windows qualification. Safe routing remains the
responsibility of the existing per-Safe Tor/SOCKS5 gateways inside the controller.

The one supported private invocation is `oblivion-vm.exe run --config PATH`.
Its supervisor must provide an inherited stdin pipe and keep its writer open;
no application bytes belong on that pipe. EOF or any byte revokes the runtime.
Configuration is a private, bounded regular file with no token or provider key.
During HCS waits the supervisor is checked at intervals of at most 100 ms.
An operation timeout is not an observation that the VM stopped.

Each configuration binds its 32-character runtime identity to its compute-system
ID, control-pipe namespace and the VHDX Identifier. The VHDX must already contain
the current runtime disk marker or ext4 identity in its **virtual block content**;
putting the marker in the VHDX container header would corrupt the container.
The helper neither initializes a disk nor adopts a disk selected by its name.
Guest preparation independently selects the configured VMBus SCSI controller
and data LUN 1 before checking the marker/UUID. Its disk selection never depends
on the assigned `sdX` name.

Kernel, initrd, ISO, data and their parent directories are held open without
delete sharing. Reparse points, hard-linked files, path aliases, unexpected
owners and writable grants to other users are rejected. Configuration and data
require private ACLs for the actual user and LocalSystem. VHDX inspection uses
the virtual-disk API for capacity, identifier, allocation subtype and loaded
state, rather than treating physical file length as virtual capacity.
Only these four pinned asset paths receive the scoped HCS VM-access grant.
The helper revokes it after a confirmed stop. If stop cannot be confirmed, it
reports failure and retains leases until process exit; grant reconciliation is
still a requirement of the Windows recovery frontend. It must not silently
reinitialize or relax the ACL on a subsequent launch.

A private, local-only VirtioSerial pipe exists before VM creation. The guest
sends READY, receives a fresh 32-byte token and acknowledges SET. The token
stays in helper memory and the guest's protected `/run`; the Linux backend uses
the same handshake implementation from `oblivion-wire`. Only then may local
control connections authenticate over AF_HYPERV to the **observed HCS RuntimeId**
and Linux vsock port 4050. The configured compute-system name is not substituted
for that runtime GUID. Bootstrap pipe peer/ACL behavior still needs a real HCS
boot; no broader permission fallback is attempted.

Control pipes verify the actual client SID and reserve their namespace between
connections. Up to 64 clients have independent bounded, zeroized bridge buffers.
Native messages are framed: after receiving a complete response, Exit or Finish,
the client closes the channel. Guest EOF drains already received output and waits
for that client close within a bounded deadline, rather than discarding unread
pipe bytes with an early disconnect. Lost clients, failed authentication and
failed cancellation do not leave a runtime accepting requests indefinitely.

Cleanup stops admission and workers and requests termination of the owned VM.
Only an HCS `Stopped` observation permits a successful stop report. The compute
system also uses `ShouldTerminateOnLastHandleClosed`; dropping a handle alone
does not qualify graceful shutdown or disk persistence. The helper creates no
saved-memory checkpoints and logs only static event identifiers. Windows paging,
crash dumps, privileged monitoring and external snapshots remain host trust
boundaries; the helper does not claim to prevent them.

From this package directory:

```sh
# Portable configuration and HCS reply tests on the development Mac/Linux:
cargo test --locked --lib --test config
# Cross-compilation only:
cargo check --locked --all-targets --target x86_64-pc-windows-msvc
# Real Windows kernel-object tests and executable linking, without creating a VM:
cargo test --locked --all-targets
cargo build --locked --bin oblivion-vm
```

The symlink fixture is explicitly ignored unless the Windows machine has the
required privilege or Developer Mode; execute it separately when available.
These tests do not prove HCS bootstrap permissions, controller boot, nested KVM,
provider login, Tor routing, persistence or the complete installation lifecycle.
