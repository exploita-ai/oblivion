# Project status

Oblivion is pre-beta. The architecture works end to end in development, but the
project is not yet ready for sensitive or irreplaceable data.

## Implemented

- amd64 Debian live boot and an arm64 Mac VM image
- encrypted general settings vault
- separate LUKS2 volume and password for each persistent session
- RAM-backed ephemeral mode
- one active session VM and volume at a time
- offline Documents mode without a network device or provider credential
- Tor and configurable SOCKS5 gateway modes with no intended direct fallback
- multiple provider keys, a global default and a per-opening override
- multiple chats sharing the documents of one encrypted session
- bounded USB import/export with manifests, hashes and recovery paths
- full-screen host manager and retained OpenCode coding-agent TUI

## Validated so far

- boot, encrypted persistence and a real provider response on physical amd64
  hardware
- lock and reopen flows on the physical USB candidate
- arm64 boot, keyboard, time zone, manager navigation and chat in the Mac VM
- automated storage, gateway, transfer and session lifecycle laboratories

Validation results belong to the commit that produced them. GitHub Actions
publishes the detailed logs and machine-readable evidence as expiring workflow
artifacts instead of storing historical snapshots in this repository.

## Release blockers

- complete the Debian package, service, binary and host-egress allowlist audit
- produce a clean release profile with all debug access removed
- repeat destructive persistence and recovery tests on a dedicated USB device
- finish long-running Tor, proxy failure and network-revocation tests
- verify multi-chat persistence and migration across image upgrades
- make builds reproducible and publish signed checksums and provenance
- commission an independent security review

## Known limitations

- cloud inference exposes approved context and output to the provider
- arm64 currently targets virtual-machine development, not booting Apple Silicon
  Macs directly from USB
- nested virtualization is not a supported release target
- the image is larger and contains more Debian tooling than the final minimal
  profile should contain
- an unlocked system holds plaintext data and credentials in RAM
- current development builds are intentionally more observable than release
  builds will be

## Near-term roadmap

1. Finish the public-source cleanup and automated secret checks.
2. Reduce and lock the Debian role manifests and enabled services.
3. Stabilize the manager, chat, Documents and multi-chat UX.
4. Build and validate an amd64 beta USB candidate.
5. Publish signed images only after the release profile passes the security
   gates above.

Local inference is a later milestone. It will add an offline inference role
without weakening the existing session-storage and network boundaries.
