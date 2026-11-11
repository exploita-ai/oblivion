- This is the Oblivion 1.0 privacy stack: native launchers and Debian Live both start a headless controller VM, which owns isolated Safe VMs and gateways. The former OpenCode fork and its `core`, `server`, `client`, `protocol`, `schema`, `sdk`, `cli` and `tui` packages are no longer present. OpenCode 2 is a pinned, unmodified guest executable alongside Codex and Claude Code.
- Keep shared Rust wire and transport types independent of controller and launcher implementations. `oblivion-cli` owns portable frontend behavior; `oblivion-host` composes the Unix launcher and Linux controller. The TypeScript manager calls the native launcher; `theme` and `tui-kit` remain reusable UI dependencies. When changing a native command or payload, update its Rust producers/consumers, the affected manager or MCP boundary schemas, and contract tests together. There is no generated OpenCode HTTP client in this tree.
- This repository does not use Changesets. Do not add `.changeset` files; follow the Oblivion release workflow instead.
- The default branch is `dev`. Base branches and worktrees on `origin/dev`, target PRs at `dev`, and diff against `origin/dev` unless told otherwise.
- Support fresh Oblivion 1.0 installations only. Keep one current implementation of each command, protocol and stored format. Remove replaced readers, aliases, migration paths and their tests/dependencies in the same change; do not retain beta compatibility or silently supply fields missing from an older internal payload. Reject unsupported formats without modifying their data. Preserve crash recovery for the current format and the native formats actually emitted by the pinned official clients.

## Manager Preview and Runtime Testing

- Run `bun run dev` from the repository root for the manager's in-memory preview. Run `bun run --cwd packages/oblivion-manager preview:ui` for its local browser framebuffer harness. Both render production components with fixture state; neither verifies a real Safe or provider connection.
- For real runtime testing, use a matching launcher, manager, native helper and controller image with disposable development state. Follow `docs/DEVELOPMENT.md`, `docs/DESKTOP.md` and `docs/ACCEPTANCE.md`; distinguish component checks from actual platform acceptance.
- Use `.opencode/skills/oblivion-dev/SKILL.md` for the current development workflow. The old `dev:live` script and shared OpenCode service workflow do not exist here.

## TUI Stories

- When a user asks for a TUI story, extend the manager's fixture preview under `packages/oblivion-manager` using `nativePreview` and the existing `script/preview-ui.tsx` harness. There is no separate legacy storybook registry.
- Render the real production component rather than a visual copy. Keep submissions and other side effects local to the story so it is safe to explore repeatedly.
- Expose meaningful state dimensions through visible preview controls or keybindings, and include a reset command when combinations can leave the fixture in a confusing state.
- Exercise 80×24 and 160×50 terminal sizes when layout is relevant. Keep preview-only controls out of production flows.

## TUI Theme Tokens

- Choose theme tokens by semantic role, not by their current color. Do not use raw `theme.hue` values or borrow an unrelated semantic token to achieve a preferred appearance.
- Use `text.feedback` and `background.feedback` only for outcome or status feedback such as errors, warnings, success messages, and informational messages. Use `formfield` states for form-control text, ordinals, and selection markers, and `action` states for actions.
- If the theme does not expose a token for the required semantic role, extend the theme schema, defaults, resolution, and types with that role before using it in a component. Do not repurpose the nearest-looking existing token.
- When changing the public theme token surface, verify the built-in light and dark defaults and the custom-theme fallback path in addition to the affected TUI component.

## Branch Names

Use a short branch name of at most three words, separated by hyphens. Do not use slashes or type prefixes such as `feat/` or `fix/`.

Examples: `session-recovery`, `fix-scroll-state`, `regenerate-sdk`.

## Commits and PR Titles

Use conventional commit-style messages and PR titles: `type(scope): summary`.

Valid types are `feat`, `fix`, `docs`, `chore`, `refactor`, and `test`. Scopes are optional; use the affected package or area when helpful, e.g. `host`, `gateway`, `manager`, `core`, `tui`, or `plugin`.

Examples: `fix(tui): simplify thinking toggle styling`, `docs: update contributing guide`, `chore(sdk): regenerate types`.

## Style Guide

### General Principles

- Keep things in one function unless composable or reusable
- Validate unknown values once at the boundary that owns them. Pass typed values inward instead of repeating `typeof value === "object"` and property-existence checks. Do not defensively revalidate values already guaranteed by a schema, constructor, or internal type.
- Do not extract single-use helpers preemptively. Inline the logic at the call site unless the helper is reused, hides a genuinely complex boundary, or has a clear independent name that improves the caller.
- Before adding complexity for a speculative or vanishingly unlikely race or security edge case, explain the concrete failure mode, likelihood, and complexity cost to the user and get their buy-in. Do not silently expand scope for theoretical robustness.
- Avoid `try`/`catch` where possible
- Avoid using the `any` type
- Use Bun APIs when possible, like `Bun.file()`
- Rely on type inference when possible; avoid explicit type annotations or interfaces unless necessary for exports or clarity
- Prefer functional array methods (flatMap, filter, map) over for loops; use type guards on filter to maintain type inference downstream
- In Effect generators, bind services to named variables before calling methods. Do not use nested service yields such as `yield* (yield* Foo.Service).bar()`.

Reduce total variable count by inlining when a value is only used once.

```ts
// Good
const journal = await Bun.file(path.join(dir, "journal.json")).json()

// Bad
const journalPath = path.join(dir, "journal.json")
const journal = await Bun.file(journalPath).json()
```

### Destructuring

Avoid unnecessary destructuring. Use dot notation to preserve context.

```ts
// Good
obj.a
obj.b

// Bad
const { a, b } = obj
```

### Imports

- Never alias imports. Do not use `import { foo as bar } from "..."` or renamed imports like `resolve as pathResolve`.
- Never use type-position `import("...")` references. Only when two imports genuinely collide on a name and no other option exists, an aliased type import (`import type { Plugin as PluginDefinition } from "..."`) is permitted as a last resort — still strongly preferred not to.
- Never use star imports. Do not use `import * as Foo from "..."` or `import type * as Foo from "..."`.
- If a namespace-style value is needed, import the module's own exported namespace by name.
- Prefer dynamic imports for heavy modules that are only needed in selected code paths, especially in startup-sensitive entrypoints. Destructure dynamic import bindings near the top of the narrowest scope that needs them so they read like normal imports. Avoid inline chains such as `await import("./module").then((mod) => mod.value())` or `(await import("./module")).value()`. Keep branch-specific imports inside the branch that needs them to preserve lazy loading.

### Variables

Prefer `const` over `let`. Use ternaries or early returns instead of reassignment.

```ts
// Good
const foo = condition ? 1 : 2

// Bad
let foo
if (condition) foo = 1
else foo = 2
```

### Control Flow

Avoid `else` statements. Prefer early returns.

```ts
// Good
function foo() {
  if (condition) return 1
  return 2
}

// Bad
function foo() {
  if (condition) return 1
  else return 2
}
```

### Complex Logic

When a function has several validation branches or supporting details, make the main function read as the happy path and move supporting details into small helpers below it.

```ts
// Good
export function loadThing(input: unknown) {
  const config = requireConfig(input)
  const metadata = readMetadata(input)
  return createThing({ config, metadata })
}

function requireConfig(input: unknown) {
  ...
}
```

- Keep helpers close to the code they support, below the main export when that improves readability.
- Do not over-abstract simple expressions into many single-use helpers; extract only when it names a real concept like `requireConfig` or `readMetadata`.
- Do not return `Effect` from helpers unless they actually perform effectful work. Synchronous parsing, validation, and option building should stay synchronous.
- Prefer Effect schema helpers such as `Schema.UnknownFromJsonString` and `Schema.decodeUnknownOption` over manual `JSON.parse` wrapped in `Effect.try` when parsing untrusted JSON strings.
- Add comments for non-obvious constraints and surprising behavior, not for obvious assignments or control flow.

### Schema Definitions (Drizzle)

Use snake_case for field names so column names don't need to be redefined as strings.

```ts
// Good
const table = sqliteTable("session", {
  id: text().primaryKey(),
  project_id: text().notNull(),
  created_at: integer().notNull(),
})

// Bad
const table = sqliteTable("session", {
  id: text("id").primaryKey(),
  projectID: text("project_id").notNull(),
  createdAt: integer("created_at").notNull(),
})
```

## Testing

- Avoid mocks as much as possible, you shouldn't be using globalThis.\* at all unless it's the only option.
- Test actual implementation, do not duplicate logic into tests
- Tests cannot run from repo root (guard: `do-not-run-tests-from-root`); run from package directories such as `packages/oblivion-manager` or `packages/oblivion-host`.
- Before writing or changing tests, read the matching skill in `.opencode/skills`: `unit-tests` for Bun tests or `tui-tests` for OpenTUI renderer tests. They cover what has made tests slow or flaky in CI.
- Run Rust checks and tests from the affected crate with `cargo check --locked` and the applicable `cargo test --locked` targets; use `.github/workflows/oblivion-check.yml` for platform dependencies and the exact suite. Run native-history Python tests from `packages/oblivion-history` with `python3 -m unittest discover -s tests -p 'test_*.py'`.

## Checks

- Run `bun run check` from the repository root as the canonical full TypeScript lint and type-check verification. It does not check Rust, Python, native helpers or built images; run the checks applicable to those changes as well.
- During focused iteration, run `bun typecheck` from the affected TypeScript package directory (for example, `packages/oblivion-manager`). Never run `tsc` directly.
- Local `typecheck` scripts use `bun check`. CI and package publishing run `typecheck:tsc`, which uses the official TypeScript compiler (`@typescript/native`). When the two disagree, `tsc` is the source of truth; reproduce with `bun run typecheck:tsc` from the package directory.
- `bun check` aims to match TypeScript 7.1, not the `7.0.2` that `process.versions.typescript` reports (oven-sh/bun#46536). When `bun check` and `tsc` from the pinned `@typescript/native` report different errors, file a minimal, dependency-free repro at https://github.com/oven-sh/bun/issues, with the output of both. `bun check` writes no declaration files, so declaration-emit errors such as TS5088 or TS2883 are expected to appear only in `tsc`; do not report those.

## Runtime and Native Agent Boundaries

- Keep desktop and Live on the shared controller-VM path. Live boot/storage integration and native desktop helpers are distinct current platform adapters, not competing generations of the product.
- Run pinned official Codex, Claude Code and OpenCode 2 executables unmodified. Preserve native argv, terminal behavior, authentication and per-agent conversation formats. Oblivion manages isolation and explicit capabilities, not an in-process model loop.
- Keep each Safe's native histories independent. `packages/oblivion-history` supports reviewed same-agent Share transfers. Do not reintroduce the retired shared-history catalog, synchronization or cross-agent conversion prototype.
- Keep Safe filesystems inside Safe VMs. Host/controller operations use the existing bounded control and transfer boundaries; do not add a direct-network fallback or mount Safe filesystems on the host.
- Keep fixtures synthetic and runtime checks isolated from personal archives, credentials and boot media. Preserve the distinction between diagnostic/laboratory images and production artifacts; generated output belongs in ignored `artifacts/`.
