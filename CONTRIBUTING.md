# Contributing to AuditPulse

Thanks for your interest in improving AuditPulse. Most of the open roadmap
issues are either new rules, new fixtures, or reporting/config
enhancements — this document covers the setup, workflow, and rule model you
need for any of them. For a hands-on walkthrough that adds one small rule
end to end, see [`docs/writing-a-rule.md`](docs/writing-a-rule.md).

## Setup

```
git clone https://github.com/Emmanuel-Ugochukwu1/auditpulse-core.git
cd auditpulse-core
npm install
npm run build
```

`npm run build` compiles TypeScript with `tsc` and also builds the native
Tree-sitter dependency chain (`tree-sitter`, `tree-sitter-rust`) that the
Rust parser relies on. If the native module ever fails to load, the scanner
still runs — it falls back to source-text-only function extraction — but
you won't get AST-verified line/column data for your changes, so a clean
build is worth confirming locally.

## The three commands that gate every change

Run these before opening a PR. CI runs the same commands, so a red result
locally will be red there too.

| Command | What it does |
| --- | --- |
| `npm test` | Runs `npm run build` first (via `pretest`), then `vitest run` — the full unit and fixture regression suite. |
| `npm run typecheck` | `tsc --noEmit` — type-checks the project without emitting output. |
| `npm run build` | `tsc` — compiles `src/` to `dist/`. |

There's also `npm run test:watch` for iterating on a fixture or rule
locally, and `npm run dev:web` to run the small local dashboard
(`http://127.0.0.1:4646`) against your changes.

## Commit style

The repository uses conventional, prefix-based commit subjects:

```
feat: add CI integration and end-to-end validation
fix: correct off-by-one in TTL extend detection
test: add admin-gated storage-resolved token fixture
docs: mark issue 13 as implemented in the roadmap
chore: add rust parser dependencies
```

Use `feat:` / `fix:` / `test:` / `docs:` / `chore:` for the corresponding
kind of change. Keep the subject line short and in the imperative mood
("add", not "added" or "adds").

## The rule model, in brief

Every check AuditPulse runs implements the shared `Rule` contract defined
in `src/types.ts`. At minimum a rule declares its identity (a stable rule
ID like `AP-CALL-001`), a severity, and the scanning logic that inspects a
file and emits findings.

Two optional capabilities, both wired up in `src/engine.ts`, let a rule opt
into richer input instead of scanning raw source text itself:

- **`FunctionRule`** — the engine hands the rule each function's parsed
  body (a `ScannedFunction`) instead of the whole file, so the rule can
  reason per-function without re-deriving function boundaries itself. Most
  of the existing rules (`missingRequireAuth`, `unprotectedUpgrade`,
  `unvalidatedExternalCall`, …) use this, because "is this operation inside
  a function that never calls `require_auth`" is naturally a per-function
  question.
- **`AstAwareRule`** — the engine additionally exposes the Tree-sitter-
  verified structural details (the `fn` keyword's line/column, the body's
  opening brace position) when the parser could confirm them, rather than
  the coarser line-only fallback used when Tree-sitter can't parse the
  file. Choose this when precise reporting locations materially help a
  reviewer (pointing at the `fn` keyword rather than just "somewhere in
  this file").

A rule that only needs whole-file, single-pass pattern matching (for
example `debugStatements`, which just looks for `log!`/`dbg!`/`println!`
calls anywhere) doesn't need either capability — plain source-text scanning
is enough, and it keeps the rule simpler.

### `ScannedFunction`: what the AST guarantees

`src/parser/rust.ts` parses each file once with Tree-sitter and extracts,
per function: its name, the `fn`-keyword line and column, the body's
opening-brace position, and the function's end line. This is what
`FunctionRule`/`AstAwareRule` consumers receive.

What it does **not** guarantee:

- **Column data is AST-verified or absent, never guessed.** If Tree-sitter
  can't parse a file (native module unavailable, or a syntax error in the
  source), scanning falls back to source-text extraction: you still get a
  line and an enclosing-function name, but no verified column.
- **No cross-file or cross-function reasoning.** Each file is scanned
  independently, and a `require_auth`/validation check inside a helper
  function does not "gate" the caller — the caller is still reported as
  unprotected. See the README's Limitations section for the specific
  consequences per rule.
- **No semantic or type analysis.** This is structural parsing (where does
  a function start and end) plus source-text heuristics within that
  boundary — not a Rust compiler frontend.

Before writing a rule that leans on exact field names of `ScannedFunction`
or the `Rule`/`FunctionRule`/`AstAwareRule` interfaces, skim `src/types.ts`
and `src/engine.ts` directly — this document describes the model and intent
accurately, but the interfaces themselves are the source of truth for exact
field names.

### Fixtures are the executable specification

`fixtures/` holds the Rust samples the regression suite (`tests/fixtures.test.ts`)
scans on every run:

```
fixtures/
  vulnerable/    # each file must trigger at least one rule
  safe/          # each file must produce zero findings
  edge-cases/    # comments/strings, odd formatting, nested blocks, coexisting findings
  workspaces/    # multi-module examples (per-file scanning semantics)
```

Every finding produced across every fixture is also swept by a
well-formedness check: each finding must carry a valid `ruleId`, a
`severity`, a non-empty `message`, and a `location` with a `file` and
`line`. `column`, `function`, `confidence`, and `remediation` are optional
and only appear when a rule can actually provide them — never invented. If
you add a rule or touch an existing one, add fixtures in the matching
folder(s) so this sweep continues to exercise your change.

## Opening a PR

- Keep the three gating commands green.
- Add or update fixtures for any rule behavior you add or change.
- Use the commit style above.
- Reference the issue you're addressing (e.g. `Closes #12`).