# Security policy

Oblivion 1.0 is security software under development. Published 0.x images belong
to the previous Live-only product; this policy describes the current source.
It has not received an independent audit and should not yet be trusted with
high-risk or irreplaceable secrets. Installed-product qualification is tracked
in the [acceptance matrix](docs/ACCEPTANCE.md).

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability and do not include real user data in a report. Use the **Report a vulnerability** button in the Security tab of `exploita-ai/oblivion` to open a private GitHub Security Advisory.

Include the affected commit or image hash, architecture, reproduction steps, expected boundary, observed boundary, and whether the report requires a debug image. We will acknowledge a valid report as soon as practical and coordinate disclosure after a fix is available.

## Security model

Oblivion is designed to reduce persistent local traces and isolate each Safe's
filesystem, processes and network from other Safes. Multiple agent sessions in
one Safe deliberately share its files and native client profiles.

The intended boundaries of the current desktop and Live implementation are:

- a native launcher managing a headless Debian controller VM on desktop and Live;
- immutable guest base images with volatile runtime paths;
- a general LUKS2 archive for the Safe catalog, application settings and saved proxy profiles;
- a separate LUKS2 volume and data key for each persistent Safe; family members can share an unlock password;
- concurrent Safe VMs with separate filesystems, opening identities and resource limits;
- offline Documents access without a network device, preserving the Safe's existing encrypted contents;
- a dedicated gateway for each online Safe, using Tor or an explicit SOCKS5 proxy;
- deny-by-default direct egress and explicit per-opening grants;
- no Safe filesystem mounted by the controller or external operating system;
- native agent profiles and credentials inside the Safe, with explicit supported credential-only delegation to a child;
- reviewed file copies through private streams, with no shared host folders;
- no production SSH, remote shell, diagnostic console, or synthetic certificate authority.

An implementation defect that crosses one of these boundaries is in scope.

The [current architecture](docs/ARCHITECTURE.md) uses the same Debian controller,
Safe, gateway and transfer boundaries behind native macOS, Linux and Windows
backends. Their qualification levels differ. Live presents only a reviewed data
partition to the controller; ephemeral Live runs do not attach that persistent
partition. Local inference is deferred beyond 1.0. Remote-provider operation is
not air-gapped or proof of host integrity.

## Important limitations

Encryption protects data at rest only after the relevant volume is locked. While
a Safe is active, its data exists in guest memory and is accessible to the
running guest and the trusted controller, outer operating system and hypervisor.

Desktop use trusts the outer operating system and hypervisor. A bare-metal Live
boot leaves the machine's installed desktop operating system inactive.
Debian's tmpfs/no-swap policy cannot prevent outer-host swap, dumps, display
capture or saved VM memory. Snapshots and suspend files may retain plaintext
and unlocked keys after a volume is closed. The qualified VM profile must
avoid automatic memory-state saving and shared host integration; this is not
a guarantee against an untrusted outer host or forensic residue. Explicit
clipboard/export actions release the selected data to their destination.

Cloud inference is not air-gapped. The configured provider receives the prompt, selected context, tool results, and response. Tor or SOCKS5 changes the network path; it does not hide submitted content from the provider.

Oblivion cannot defend against compromised firmware, malicious hardware,
physical capture of an unlocked machine, display or keyboard interception, or
an unknown vulnerability in its operating systems, hypervisors, cryptsetup,
Tor, official agent clients or other dependencies.

The permission UI of the coding agent is not the security sandbox. Isolation
comes from the Safe VM, device model, filesystem boundary, gateway and controller
policy. Personal encrypted-volume backups may contain saved agent credentials;
portable Share excludes known credential stores but cannot remove arbitrary
secrets written into selected conversations or files.

## In scope

- plaintext Safe or credential data written outside the intended encrypted volume;
- secrets in logs, crash dumps, process arguments, environment dumps, or temporary files;
- access from one Safe to another outside explicit scoped operations;
- the controller or external operating system mounting or exposing a Safe filesystem;
- direct guest egress, DNS leaks, or fallback around the selected transport;
- reuse of revoked opening grants or delegated capabilities;
- release images containing debug access or laboratory trust anchors;
- path traversal or boundary escape in document import/export;
- persistence changes made by ephemeral mode;
- stale cleanup, grants or jobs affecting a different Safe opening or a reused VM slot.

## Usually out of scope

- content deliberately sent to the configured model provider;
- a provider retaining data contrary to its own policy;
- attacks requiring an already compromised BIOS, kernel, or physical machine;
- denial of service without a boundary violation;
- findings that exist only in clearly labelled synthetic laboratory fixtures and cannot reach a release image;
- generic upstream dependency findings without an Oblivion-specific impact or reproduction.

## Development material

The repository includes clearly marked synthetic credential strings for isolated
network tests. Short-lived TLS identities are generated during each laboratory
build or test and are never committed. They have no production authority, and
production builds must not trust or install laboratory roots. Real API keys,
Wi-Fi credentials, session volumes, packet captures, generated images, and user
documents must never be committed.

Every release candidate should be reproducible from a public commit, publish checksums, identify its Debian snapshot and toolchain, pass the repository and VM suites, and document all remaining exceptions. Those release gates are still being completed.
