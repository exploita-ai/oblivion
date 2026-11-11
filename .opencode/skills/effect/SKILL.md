---
name: effect
description: Work on the Effect v4 schemas used by Oblivion's terminal theme package. Use when editing Effect imports or schema decoding in this repository.
---

# Effect schemas

The maintained Effect usage is in `packages/theme/src/tui/schema.ts` and
`packages/theme/src/tui/resolve.ts`. The old Effect HTTP server, service layers
and `packages/core` test helpers are no longer part of Oblivion. Do not introduce
those patterns merely because this dependency remains.

Check the pinned `effect` version in root `package.json` and the installed
package's source/types before choosing APIs; older v2/v3 examples are not the
contract. `.opencode/references/effect`, if present, is optional local research,
not a tracked dependency or automatically the same version. Verify its version
before relying on it; do not clone an unpinned upstream tree as routine setup.

Follow the existing synchronous `Schema` definitions and boundary decoders.
Validate unknown theme documents once, then pass typed values into resolution.
Do not add Effect runtimes, service layers, unchecked casts or `any` to solve a
synchronous parsing problem. If effectful work is actually needed, keep its
scope explicit and follow the root style rules.

Theme roles are semantic. When extending the public token surface, update the
schema, types, defaults and resolution together, and verify light, dark and
custom-theme fallback behavior with the affected production component. See
root `AGENTS.md` and the [TUI testing skill](../tui-tests/SKILL.md).

From `packages/theme`, run `bun typecheck`; use `bun run typecheck:tsc` when
investigating a compiler disagreement. Run relevant tests from their package
directories. There is no `testEffect` or `it.live` repository helper to import.
