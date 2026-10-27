# Changelog

## Unreleased

### Added

- Minimal Debian live-system builder for amd64 and arm64.
- General LUKS2 vault for host settings and credentials.
- Independent LUKS2 volumes for persistent sessions and an optional ephemeral mode.
- One-session-at-a-time VM controller with offline Documents and chat modes.
- Tor and configurable SOCKS5 gateway with deny-by-default direct access.
- OpenTUI host manager, OpenCode-derived coding agent, document import/export, and multiple chats per session.
- Mac virtualization laboratory, physical boot-media validation flow, and machine-readable security evidence.

### Security

- Disabled logging, telemetry, update checks, provider discovery, crash dumps, and project configuration in the Oblivion agent profile.
- Kept laboratory diagnostics and synthetic credentials out of production image stages.

This project is still pre-beta and has not received an independent security audit.
