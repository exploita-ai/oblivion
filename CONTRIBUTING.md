# Contributing to Oblivion

Oblivion combines a Debian live image, encrypted storage, isolated VMs, a network gateway, and an OpenCode-derived coding agent. Changes at one boundary can invalidate assumptions at another, so contributions should be narrow, testable, and explicit about the threat model.

## Before opening a pull request

1. Open an issue for architectural, privacy, storage, or network changes.
2. Explain which trust boundary changes and what new data can cross it.
3. Keep production behavior separate from laboratory and debug behavior.
4. Never use real credentials, user conversations, captured production traffic, or private documents as fixtures.

The default branch is `dev`. Use a short branch name of at most three hyphen-separated words and conventional commit titles such as `fix(gateway): revoke stale grants`.

## Development setup

Oblivion pins Bun in `package.json`.

```sh
bun install --frozen-lockfile
bun run check
```

Run tests from the affected package, never from the repository root:

```sh
cd packages/oblivion-manager
bun test
bun typecheck

cd ../oblivion-host
cargo test --locked
```

The VM and image tests are under `script/oblivion`. Many need Docker, QEMU, hardware acceleration, or several gigabytes of temporary disk space. Their output belongs in the ignored `artifacts/` directory.

## Agent and TUI changes

The retained `@opencode/*` packages are the coding-agent runtime, not unused upstream baggage. Preserve their dependency direction and the existing OpenTUI interaction model.

- Prefer `bun run dev:live [directory]` for live TUI work.
- Read the matching testing guide in `.opencode/skills` before changing tests.
- Run `bun run generate` from `packages/client` after changing the public Protocol or Server `HttpApi`.
- Do not edit generated client files directly.
- Use semantic theme tokens rather than raw colors or unrelated status tokens.

## Privacy requirements

A change is incomplete if it works only on the happy path. Include relevant failure cases:

- process crash, timeout, cancellation, and power loss;
- partial frames and disconnected control channels;
- failed LUKS close or a still-busy filesystem;
- gateway loss, proxy rejection, and stale network state;
- removable media disappearing during a transfer;
- secrets in argv, environment variables, logs, diagnostics, core dumps, and temporary files.

Do not add a direct-network fallback. Do not mount session filesystems on the host. Do not make debug access part of a release image.

## Pull requests

Keep the description short and concrete:

- what changed;
- why the previous behavior was wrong or insufficient;
- which trust boundary is affected;
- exact commands and environments used for verification;
- remaining limitations.

UI changes should include screenshots at 80×24 and a larger terminal. Storage and network changes should include machine-readable evidence where the existing suites already produce it.

## Upstream OpenCode changes

When possible, keep generic agent improvements suitable for OpenCode separate from Oblivion-specific policy. Preserve the upstream MIT notices and document substantial imported updates in the pull request.
