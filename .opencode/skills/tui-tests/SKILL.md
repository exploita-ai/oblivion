---
name: tui-tests
description: Write, review or debug OpenTUI renderer tests for Oblivion's manager and tui-kit, including fixture state, frames, clocks, keyboard input, resize and cleanup.
---

# TUI renderer tests

Read root `AGENTS.md` for semantic theme tokens, fixture previews and test
isolation. Current suites live in `packages/oblivion-manager/test` and
`packages/tui-kit/test`; the former OpenCode `packages/tui` fixtures and
storybook no longer exist. For interactive checks use
[oblivion-dev](../oblivion-dev/SKILL.md); for non-rendering subprocess tests use
[unit-tests](../unit-tests/SKILL.md).

## Render production components

Use `testRender` from `@opentui/solid` with explicit `width` and `height`. Feed
the real component through its existing props and `NativeRuntime` interface.
`nativePreview` in `packages/oblivion-manager/src/native-control.ts` provides
in-memory fixture state for the manager; narrow tests can provide only the
runtime operations they exercise. Keep submissions and mutations local.

Prefer the non-started renderer for component tests: change state, await
`app.renderOnce()`, and inspect `app.captureCharFrame()`. See
`packages/tui-kit/test/select-list.test.tsx` and the manager's
`test/native-storage.test.tsx`. Assert behavior and visible content rather than
maintaining a second implementation or a visual copy of the component.

## Await the right signal

An asynchronous status request is not complete just because a frame rendered.
Use an explicit deferred promise when testing loading, failure or retry, await
its resolution, then render. The manager's `test/startup.test.tsx` combines
`Promise.withResolvers` with a real `statusReader` to exercise this boundary.

For renderer-driven timing, pass `ManualClock` from `@opentui/core/testing`,
advance it and render; startup tests cover the three-second logo without
sleeping. Do not treat frame counts as milliseconds. A frame-budget failure
requires checking the wait condition and renderer mode; raising Bun's timeout
does not fix it. A visually idle frame may still precede pending application
work. Avoid global fake timers when an existing clock can drive the behavior.

## Input and layout

- Use `app.mockInput` for keys, arrows, paste and mouse actions. Set
  `kittyKeyboard: true` for keyboard interaction tests, matching current
  fixtures, and await asynchronous input methods before asserting.
- Ensure the intended control is focused before typing. Test keyboard-only
  navigation and disabled actions where relevant.
- Exercise 80×24 and 160×50 for manager layout changes. After `app.resize`,
  render again before checking the frame. Smaller component-specific sizes can
  additionally cover clipping and overflow.
- Use synthetic Unicode names, spaces and paste payloads for Files behavior;
  do not use personal paths, real archive contents or credentials.
- Use semantic theme roles. A public token change needs light, dark and custom
  fallback verification in addition to the affected component.

## Cleanup and verification

Always `await app.dispose()` in `finally`, as the current suites do. Dispose
components and close fixture resources before removing temporary directories;
pending callbacks must not write into the next test or a destroyed renderer.

Run from the affected package:

```sh
cd packages/oblivion-manager
bun test --timeout 30000 test/startup.test.tsx
bun typecheck
```

Repeat a case when diagnosing a race, and inspect its first failure instead of
hiding it with sleeps, broad timeouts or platform skips. Passing renderer tests
establishes local UI behavior; it does not qualify real terminal handoff,
native file pickers, controller state or guest VM operation.
