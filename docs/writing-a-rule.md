# Writing a rule

This walks through adding one small example rule end to end: the plugin
file, its registry entry, tests, and fixtures. It uses a deliberately
simple check so the shape of the work is clear; see
[`CONTRIBUTING.md`](../CONTRIBUTING.md) for the concepts (`Rule`,
`FunctionRule`, `AstAwareRule`, `ScannedFunction`) referenced below.

> The field and method names shown here follow the model described in
> `CONTRIBUTING.md` and the conventions visible across the existing rules
> (`AP-AUTH-001`, `AP-UPG-001`, etc.). Skim `src/types.ts` and
> `src/engine.ts` before you start and adjust names to match exactly —
> treat the code here as a template for the *shape* of a contribution,
> not a byte-for-byte source dump.

## The example rule

We'll add **`AP-DOC-001` — `unresolvedTodo`**: flag `// TODO` / `// FIXME`
comments left in contract source, on the theory that an unresolved TODO in
a function touching funds or auth is worth a reviewer's attention before
mainnet deployment. It's:

- **Low severity, high confidence** — like `AP-DEBUG-001`, this is a hygiene
  signal, not a vulnerability class. It should never block a build; it
  should just show up in the report.
- A **whole-file, source-text rule** — it doesn't need per-function
  reasoning or AST-verified columns, so it doesn't need the `FunctionRule`
  or `AstAwareRule` capabilities. This mirrors `debugStatements`, which is
  the simplest existing rule to model a new one on.

## 1. The plugin file

Rule plugins live in `src/plugins/`, one file per rule, named for the rule
(camelCase, matching the pattern of `unprotectedUpgrade.ts` for
`AP-UPG-001`). Create `src/plugins/unresolvedTodo.ts`:

```typescript
import type { Rule } from '../types';

const TODO_PATTERN = /\/\/\s*(TODO|FIXME)\b/i;

export const unresolvedTodo: Rule = {
  id: 'AP-DOC-001',
  summary: 'Unresolved TODO/FIXME comment left in contract source',
  severity: 'low',
  confidence: 'high',

  scan(file) {
    const findings = [];
    const lines = file.source.split('\n');

    lines.forEach((line, index) => {
      if (TODO_PATTERN.test(line)) {
        findings.push({
          ruleId: this.id,
          severity: this.severity,
          confidence: this.confidence,
          message:
            'Unresolved TODO/FIXME comment left in contract source. ' +
            'Review before deploying to mainnet.',
          location: {
            file: file.path,
            line: index + 1,
          },
          remediation:
            'Resolve the TODO/FIXME or convert it into a tracked issue, ' +
            'then remove the comment.',
        });
      }
    });

    return findings;
  },
};
```

A couple of things worth calling out for a first rule:

- **Prefer silence over noise.** This is the same principle every existing
  rule follows (see the README's Limitations section) — if you can't be
  confident a pattern is a real issue, either raise the required evidence
  bar or drop the confidence to `low` rather than flagging aggressively.
- **Only populate fields you can actually support.** `column` and
  `function` are omitted here because a source-text rule can't verify
  them — never fill them with a guess.

## 2. Registry entry

New rules are registered in `src/engine.ts` alongside the existing plugin
imports, so the CLI and web API both pick them up automatically. Add the
import and add the rule to the shared rule list/registry the engine
iterates over — follow the exact pattern the other six rules already use
there (import the named export, add it to the collection the engine scans
with). If you also gate rules through `auditpulse.toml`'s
`disabled_rules`, confirm your new rule ID is recognized by that config
path too.

## 3. Fixtures

Add one fixture per fixture category your rule is meant to cover:

```
fixtures/vulnerable/unresolved_todo.rs   # contains at least one // TODO or // FIXME
fixtures/safe/unresolved_todo_clean.rs   # no TODO/FIXME comments at all
fixtures/edge-cases/unresolved_todo_in_string.rs
  # a string literal containing the text "TODO" (must NOT trigger the rule)
```

`fixtures/vulnerable/unresolved_todo.rs`:

```rust
pub fn withdraw(env: Env, account: Address, amount: i128) {
    env.require_auth();
    // TODO: add a minimum withdrawal check before mainnet
    let balance = read_balance(&env, &account);
    write_balance(&env, &account, balance - amount);
}
```

`fixtures/safe/unresolved_todo_clean.rs`:

```rust
pub fn withdraw(env: Env, account: Address, amount: i128) {
    env.require_auth();
    let balance = read_balance(&env, &account);
    write_balance(&env, &account, balance - amount);
}
```

These fixtures are picked up automatically by `tests/fixtures.test.ts`,
which scans every file under `fixtures/vulnerable` and `fixtures/safe` and
asserts the expected non-zero / zero finding counts, plus the
well-formedness sweep described in `CONTRIBUTING.md` (every finding has a
valid `ruleId`, `severity`, `message`, and `location.file`/`location.line`).

## 4. A focused unit test

Beyond the fixture sweep, add a small rule-specific test — following the
pattern of `tests/authOrdering.test.ts` for `AP-AUTH-001` — for behavior
that a generic fixture pass/fail count wouldn't catch on its own, such as
the string-literal edge case:

```typescript
import { describe, it, expect } from 'vitest';
import { scan } from '../src/engine';

describe('AP-DOC-001 unresolvedTodo', () => {
  it('flags a TODO comment', () => {
    const source = `
      pub fn withdraw(env: Env) {
        // TODO: add bounds check
      }
    `;
    const findings = scan(source, 'test.rs');
    expect(findings.some((f) => f.ruleId === 'AP-DOC-001')).toBe(true);
  });

  it('does not flag TODO inside a string literal', () => {
    const source = `
      pub fn log_status(env: Env) {
        log!(&env, "TODO items remaining: {}", 0);
      }
    `;
    const findings = scan(source, 'test.rs');
    expect(findings.some((f) => f.ruleId === 'AP-DOC-001')).toBe(false);
  });
});
```

(The second case is a known limitation to design for, not necessarily to
solve on day one — see the note on preferring silence over noise. If your
first pass can't distinguish comments from string contents, it's fine to
document that as a limitation rather than ship a false negative silently.)

## 5. Verify

```
npm run typecheck
npm test
```

`npm test` runs the full fixture regression suite plus your new focused
test. Also try the rule manually against the example contracts:

```
node dist/index.js scan examples/vulnerable_vault.rs
node dist/index.js scan examples/safe_vault.rs
```

## 6. Document it

Add a row to the README's Checks list and Severity/Confidence table, and
mention the rule in your PR description along with which fixture
categories you covered.