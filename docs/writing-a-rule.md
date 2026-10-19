# Writing a Rule Walkthrough

This guide walks through creating, testing, and registering a new security rule in AuditPulse Core from start to finish.

We will build an example rule: **`AP-CAST-001` (Unsafe Integer Truncation)**, which detects unchecked integer type narrowing (e.g., casting `u128`/`i128` down to `u32`/`u64` using `as u32` or `as u64` on amount-like variables).

---

## Overview of the Workflow

Adding a new rule involves five modular steps:

1. **Implement the rule plugin** in `src/plugins/<ruleName>.ts`.
2. **Register the rule** in `src/registry.ts`.
3. **Write unit tests** in `tests/<ruleName>.test.ts`.
4. **Add contract fixtures** in `fixtures/vulnerable/` and `fixtures/safe/`.
5. **Verify against gating checks** (`npm run typecheck`, `npm run build`, `npm test`).

---

## Step 1: Implement the Rule Plugin

Create a new file `src/plugins/unsafeIntegerCast.ts`.

Rules should implement the `Rule` interface (`src/types.ts`) and, when analyzing functions, the `FunctionRule` capability (`src/engine.ts`).

```typescript
import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { FunctionRule } from "../engine.js";
import { extractRustFunctions, sanitizeKeepLines } from "../utils/rust.js";
import { findExpressionLocation } from "../parser/rust.js";

/** Amount-like identifier patterns */
const AMOUNT_PATTERN =
  /\b(?:amount|balance|supply|fee|deposit|withdraw|reward|shares)\w*\b/i;

/** Unchecked narrowing casts */
const NARROWING_CAST = /\bas\s+(?:u8|u16|u32|u64|i8|i16|i32|i64)\b/;

export class UnsafeIntegerCastPlugin implements Rule, FunctionRule {
  id = "AP-CAST-001";
  name = "Unsafe Integer Cast";
  description =
    "Detects narrowing integer casts on amount-like values without overflow checks, which can cause silent truncation";

  /** Whole-source scan: used when tree-sitter AST is bypassed or in standalone execution */
  scan(code: string): Vulnerability[] {
    const clean = sanitizeKeepLines(code);
    return extractRustFunctions(clean).flatMap((fn) => this.scanFunction(fn));
  }

  /**
   * Scans a single function extracted by the AuditEngine AST parser.
   * Tree-sitter parses the file once and shares ScannedFunction instances.
   */
  scanFunction(fn: ScannedFunction): Vulnerability[] {
    const clean = sanitizeKeepLines(fn.body);
    const openBrace = clean.indexOf("{");
    const bodyLines = (openBrace >= 0 ? clean.slice(openBrace + 1) : clean).split("\n");

    const findings: Vulnerability[] = [];

    for (let i = 0; i < bodyLines.length; i++) {
      const line = bodyLines[i] ?? "";

      if (AMOUNT_PATTERN.test(line) && NARROWING_CAST.test(line)) {
        // Target finding line (1-based index)
        const lineOffset = fn.bodyLine + i;
        
        // Precise expression column location
        const loc = findExpressionLocation(fn.body, NARROWING_CAST, fn.line);

        findings.push({
          id: this.id,
          message: `Amount-like variable in function '${fn.name}' undergoes narrowing integer cast with 'as', which may truncate high bits.`,
          severity: "high",
          confidence: "high",
          location: {
            line: loc ? loc.line : lineOffset,
            column: loc?.column,
            function: fn.name,
          },
          remediation:
            "Use checked conversions such as u32::try_from(...) or avoid downcasting balance and amount variables.",
        });
      }
    }

    return findings;
  }
}

export default new UnsafeIntegerCastPlugin();
```

### Key Practices for Rule Plugins:

1. **Keep Line Structure Honest**: Always use `sanitizeKeepLines` when preprocessing source code. It blanks out comments and strings with spaces so that line and column numbers remain strictly identical to the original source.
2. **Column Precision**: When identifying offending calls or operators, call `findExpressionLocation(fn.body, regex, fn.line)` to provide exact column numbers for IDE and SARIF viewers.
3. **Idempotency**: Rule instances must be stateless across invocations.

---

## Step 2: Register the Rule

Register the new rule plugin in `src/registry.ts`:

```typescript
// src/registry.ts
import UnsafeIntegerCastPlugin from "./plugins/unsafeIntegerCast.js";

export function createDefaultRegistry(): RuleRegistry {
  return new RuleRegistry()
    .register(MissingRequireAuthPlugin)
    .register(UnwrapUsagePlugin)
    .register(MissingExtendTtlPlugin)
    .register(UncheckedArithmeticPlugin)
    .register(UnvalidatedExternalCallPlugin)
    .register(UnprotectedUpgradePlugin)
    .register(DebugStatementsPlugin)
    .register(UnsafeIntegerCastPlugin); // Add here
}
```

---

## Step 3: Write Unit Tests

Add targeted unit tests in `tests/unsafeIntegerCast.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import UnsafeIntegerCastPlugin from "../src/plugins/unsafeIntegerCast";

describe("AP-CAST-001 (UnsafeIntegerCastPlugin)", () => {
  it("detects narrowing integer casts on amount identifiers", () => {
    const code = `
      fn process_fee(env: Env, fee: u128) {
        let small_fee = fee as u32;
      }
    `;

    const vulns = UnsafeIntegerCastPlugin.scan(code);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]?.id).toBe("AP-CAST-001");
    expect(vulns[0]?.severity).toBe("high");
    expect(vulns[0]?.location.function).toBe("process_fee");
    expect(vulns[0]?.location.line).toBe(3);
  });

  it("ignores safe conversions or non-amount values", () => {
    const code = `
      fn safe_convert(env: Env, fee: u128) {
        let small_fee = u32::try_from(fee).unwrap();
        let loop_idx = index as u32;
      }
    `;

    const vulns = UnsafeIntegerCastPlugin.scan(code);
    expect(vulns).toHaveLength(0);
  });
});
```

---

## Step 4: Add Fixtures & Fixture Quality Sweep

Fixtures ensure the entire scanning engine, CLI, and SARIF output handle real contracts properly.

1. **Add a vulnerable contract** in `fixtures/vulnerable/unsafe_cast.rs`:
   ```rust
   use soroban_sdk::{contractimpl, Env, Address};

   pub struct Vault;

   #[contractimpl]
   impl Vault {
       pub fn withdraw(env: Env, amount: u128) {
           let truncated = amount as u32;
       }
   }
   ```

2. **Add a safe reference contract** in `fixtures/safe/safe_cast.rs`:
   ```rust
   use soroban_sdk::{contractimpl, Env, Address};

   pub struct Vault;

   #[contractimpl]
   impl Vault {
       pub fn withdraw(env: Env, amount: u128) {
           let safe_val = u32::try_from(amount).expect("overflow");
       }
   }
   ```

3. **Include the fixture in `tests/fixtures.test.ts`**:
   Add test assertions in `tests/fixtures.test.ts` verifying that `unsafe_cast.rs` trips `AP-CAST-001` while `safe_cast.rs` stays silent.
   Ensure the fixture paths are included in `allFixtures` so the **finding quality sweep** verifies finding ID format, severity, confidence, and remediation messages.

---

## Step 5: Verification

Run the gating verification suite:

```bash
# Verify TypeScript types
npm run typecheck

# Verify build output
npm run build

# Run Vitest test suite
npm test
```

Once all checks pass cleanly, you are ready to open a pull request!
