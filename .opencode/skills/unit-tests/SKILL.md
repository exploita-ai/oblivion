---
name: unit-tests
description: Write, review or fix Bun unit and subprocess tests in Oblivion's manager, MCP tools and UI utilities. For tests that render OpenTUI components, use tui-tests.
---

# Bun tests

Read root `AGENTS.md` for style, test isolation and checks. The TypeScript
workspaces are `oblivion-manager`, `oblivion-tools`, `theme` and `tui-kit`.
Rust and Python have separate package-local suites; use the current
`.github/workflows/oblivion-check.yml` for the exact platform jobs. The old
OpenCode `core`, `client`, `server`, `app` and shared test helpers are absent.

## Run the relevant suite

Run from the affected package, never the repository root:

```sh
cd packages/oblivion-manager
bun test --timeout 30000 test/native-agent.test.ts
bun typecheck
```

Use the package's test-script timeout when running a file directly. During a
flakiness investigation, repeat the affected case with `--rerun-each`; do not
repeat all suites after they pass without a new failure or concern. The root
`bun run check` covers TypeScript lint/types, not test execution.

## Test the real boundary

- Import production functions and assert observable results. Avoid module or
  `globalThis` mocks; pass fixture dependencies through existing interfaces.
- Use a real subprocess when argv, inherited descriptors, exit status, signals
  or stdio are the behavior under test. See the manager's
  `test/native-agent.test.ts` and tools' `test/stdio.test.ts`. Keep pure parsing
  and validation in-process rather than spawning a program for every case.
- For MCP transport behavior, `packages/oblivion-tools/test/safe-tools.test.ts`
  exercises real sockets and the built stdio endpoint. Keep its local peer
  synthetic; never require a provider account or a user's running Safe.
- Create unique temporary directories, bind TCP servers to port `0`, and close
  sockets/processes before removing their files. Restore environment and other
  process state in `finally` or teardown. Tests must not depend on invocation
  order or a shared `/tmp` path.
- Test malformed input, cancellation and uncertain replies where the boundary
  owns those cases. Assert that a lost creation reply does not accidentally
  cause an automatic retry. Do not duplicate protocol implementation in tests
  simply to match its output.

## Time and platform behavior

Wait for the actual promise, callback or process event instead of sleeping for
an assumed duration. Use bounded polling only when there is no completion
signal. Avoid speed assertions based on elapsed wall time; slow CI is not a
functional failure. Renderer clocks and frames are covered by
[tui-tests](../tui-tests/SKILL.md).

A timed-out Bun test can leave pending work that fails the next test. Inspect
the first failure and clean up resources rather than increasing all timeouts.
When increasing a timeout for real work, name that work in a nearby comment.
Do not add concurrency or runner flags as a substitute for fixing isolation.

Platform skips need a real API boundary: the manager's descriptor-3 POSIX
handoff tests intentionally skip Windows, whose adapter differs. Do not hide
timing flakes behind platform skips. Compare the actual workflow jobs and
logs; passing on one OS does not qualify another OS or a VM backend.

Workspace packages export source, so ordinary tests should not require stale
`dist` output. A transport/build contract can deliberately build its own
temporary artifact, as the MCP tests do. Keep generated output out of Git.
