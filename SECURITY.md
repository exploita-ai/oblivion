# Security policy

Oblivion is pre-beta security software. It has not received an independent audit and should not yet be trusted with high-risk or irreplaceable secrets.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability and do not include real user data in a report. Use the **Report a vulnerability** button in the Security tab of `exploita-ai/oblivion` to open a private GitHub Security Advisory.

Include the affected commit or image hash, architecture, reproduction steps, expected boundary, observed boundary, and whether the report requires a debug image. We will acknowledge a valid report as soon as practical and coordinate disclosure after a fix is available.

## Security model

Oblivion is designed to reduce persistent local traces and to isolate each protected session from the host and from other sessions.

The intended boundaries are:

- an immutable Debian live root with volatile runtime paths;
- a general LUKS2 vault for host preferences and credentials;
- a different LUKS2 volume and password for every persistent session;
- one active session VM and volume at a time;
- an offline Documents VM with no network device or provider credential;
- a dedicated gateway VM for Tor or an explicit SOCKS5 proxy;
- deny-by-default direct egress and explicit per-opening grants;
- no session filesystem mounted on the host;
- no production SSH, remote shell, diagnostic console, or synthetic certificate authority.

An implementation defect that crosses one of these boundaries is in scope.

## Important limitations

Encryption protects data at rest only after the relevant volume is locked. While a session is active, its data exists in guest memory and is accessible to the running guest, host kernel, and physical machine.

Cloud inference is not air-gapped. The configured provider receives the prompt, selected context, tool results, and response. Tor or SOCKS5 changes the network path; it does not hide submitted content from the provider.

Oblivion cannot defend against compromised firmware, malicious hardware, physical capture of an unlocked machine, display or keyboard interception, or an unknown vulnerability in Debian, QEMU, Linux, cryptsetup, Tor, OpenCode, or another dependency.

The permission UI of the coding agent is not the security sandbox. Isolation comes from the session VM, device model, filesystem boundary, gateway, and host policy.

## In scope

- plaintext session or credential data written outside the intended encrypted volume;
- secrets in logs, crash dumps, process arguments, environment dumps, or temporary files;
- access from one protected session to another;
- host mounting or exposing a session filesystem;
- direct guest egress, DNS leaks, or fallback around the selected transport;
- reuse of revoked API keys or session grants;
- release images containing debug access or laboratory trust anchors;
- path traversal or boundary escape in document import/export;
- persistence changes made by ephemeral mode;
- bypass of the one-session-at-a-time invariant.

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
