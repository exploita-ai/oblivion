---
name: oblivion-dev
description: Run or debug the Oblivion manager preview and choose the appropriate launcher, controller or Live development workflow. Use for interactive Oblivion UI checks and runtime investigations in this repository.
---

# Oblivion development

This repository builds Oblivion's privacy stack. The old OpenCode client/server
packages and `dev:live` command are gone. Codex, Claude Code and OpenCode 2 run as
pinned official executables inside Safe VMs. Read [the development guide](../../../docs/DEVELOPMENT.md)
for current build commands and [the architecture](../../../docs/ARCHITECTURE.md)
when investigating a runtime boundary.

## Preview the manager

From the repository root:

```sh
bun run dev
```

This starts `packages/oblivion-manager/src/index.tsx --preview`, rendering the
production manager against `nativePreview` in `src/native-control.ts`. It changes
fixture state only. For browser inspection of the real OpenTUI framebuffer:

```sh
bun run --cwd packages/oblivion-manager preview:ui
```

The harness prints its loopback URL and uses an available port by default.
`OBLIVION_PREVIEW_PORT` selects a port when needed. Its controls support keyboard,
paste, resize and reset; it never connects to the controller. Stop the process
you started after the check. Do not repurpose unrelated terminal sessions.

Inspect 80×24 and 160×50 when layout matters. Check keyboard focus, visible
actions, paste and resize using synthetic values. Add fixture-driven previews
around the production component, with visible controls and reset; keep preview
side effects local. Renderer tests belong in `packages/oblivion-manager/test`
or `packages/tui-kit/test`; use the [TUI testing skill](../tui-tests/SKILL.md).

## Investigate the real runtime

The manager invokes the native launcher through `src/native-control.ts` and the
file/USB adapters. Shared frontend behavior lives in `packages/oblivion-cli`;
`packages/oblivion-host` composes the Unix launcher and Linux controller. Native
helpers live in `oblivion-native`, `oblivion-native-linux` and
`oblivion-native-windows`. Desktop and Live both start a controller VM; Safe and
gateway VMs run inside it.

Use a matched launcher, manager, platform helper and controller image with a
disposable development installation. Follow [desktop setup](../../../docs/DESKTOP.md),
[Live setup](../../../docs/LIVE.md) and the exact commands supported by the
[CLI](../../../docs/CLI.md). An existing personal archive or arbitrary attached
disk is not a test fixture. Build output and synthetic evidence belong under
ignored `artifacts/`. The root `build:live` and `build:runtime` scripts build the
Live image and controller image respectively; `build:deb` builds the inner
controller package, not a desktop installer.

Check the boundary that owns the failure: native helper/controller startup,
controller status, Safe lifecycle, transfer protocol or rendered UI. Avoid
collecting credentials, real conversation content or private files for debugging.
Preview success and mocked controller replies cannot establish VM isolation,
provider login, persistence, network behavior or native terminal acceptance.
Record the tested commit, artifact and environment against
[the acceptance matrix](../../../docs/ACCEPTANCE.md).

Run `bun run check` for TypeScript and the affected package-local tests. Use
`.github/workflows/oblivion-check.yml` for platform-specific checks; a passing
TypeScript check does not compile the Rust controller or native helpers.
