import { describe, it, expect } from "vitest";
import MissingRequireAuthPlugin from "../src/plugins/missingRequireAuth";
import UncheckedArithmeticPlugin from "../src/plugins/uncheckedArithmetic";
import UnvalidatedExternalCallPlugin from "../src/plugins/unvalidatedExternalCall";
import UnprotectedUpgradePlugin from "../src/plugins/unprotectedUpgrade";
import DebugStatementsPlugin from "../src/plugins/debugStatements";
import UnwrapUsagePlugin from "../src/plugins/unwrapUsage";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import type { Vulnerability } from "../src/types";

/**
 * Shared shape assertions: every finding must carry a stable id, severity,
 * confidence, source location, a useful message, and remediation guidance.
 */
function expectWellFormedFinding(finding: Vulnerability, id: string): void {
  expect(finding.id).toBe(id);
  expect(finding.severity).toBeTruthy();
  expect(finding.confidence).toBeTruthy();
  expect(finding.location.line).toBeGreaterThan(0);
  expect(finding.message.length).toBeGreaterThan(10);
  expect(finding.remediation).toBeTruthy();
  expect(finding.remediation!.length).toBeGreaterThan(10);
}

describe("UncheckedArithmeticPlugin (AP-ARITH-001)", () => {
  it("detects balance subtraction without checked math", () => {
    const code = `
      fn withdraw(env: Env, user: Address, amount: i128) {
        let mut balance: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        balance = balance - amount;
        env.storage().persistent().set(&user, &balance);
      }
    `;

    const findings = UncheckedArithmeticPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expectWellFormedFinding(findings[0]!, "AP-ARITH-001");
    expect(findings[0]?.severity).toBe("medium");
    expect(findings[0]?.confidence).toBe("medium");
    expect(findings[0]?.location.function).toBe("withdraw");
    expect(findings[0]?.location.line).toBe(4);
    expect(findings[0]?.remediation).toContain("checked_sub");
  });

  it("detects amount addition and multiplication on other lines", () => {
    const code = `
      fn deposit(env: Env, user: Address, amount: i128) {
        let balance: i128 = get(env, &user);
        put(env, &user, balance + amount);
      }

      fn double_rewards(env: Env, user: Address) -> i128 {
        let rewards: i128 = get(env, &user);
        rewards * 2
      }
    `;

    const findings = UncheckedArithmeticPlugin.scan(code);

    expect(findings).toHaveLength(2);
    expect(findings[0]?.location.line).toBe(4);
    expect(findings[1]?.location.line).toBe(9);
    expect(findings[1]?.location.function).toBe("double_rewards");
  });

  it("ignores checked arithmetic", () => {
    const code = `
      fn withdraw(env: Env, user: Address, amount: i128) -> Result<(), Error> {
        let balance: i128 = get(env, &user);
        let remaining = balance.checked_sub(amount).ok_or(Error::Underflow)?;
        put(env, &user, remaining);
        Ok(())
      }
    `;

    expect(UncheckedArithmeticPlugin.scan(code)).toHaveLength(0);
  });

  it("ignores saturating and bounded math", () => {
    const code = `
      fn deposit(env: Env, user: Address, amount: i128) {
        let balance: i128 = get(env, &user);
        let capped = balance.saturating_add(amount.min(MAX_STEP));
        put(env, &user, capped);
      }
    `;

    expect(UncheckedArithmeticPlugin.scan(code)).toHaveLength(0);
  });

  it("ignores plain local counters without amount-like names", () => {
    const code = `
      fn bump(env: Env) -> u32 {
        let mut calls = env.storage().instance().get(&CALLS).unwrap_or(0u32);
        calls = calls + 1;
        env.storage().instance().set(&CALLS, &calls);
        calls
      }
    `;

    expect(UncheckedArithmeticPlugin.scan(code)).toHaveLength(0);
  });

  it("ignores unrelated arithmetic on non-amount variables", () => {
    const code = `
      fn midpoint(a: i128, b: i128) -> i128 {
        (a + b) / 2
      }
    `;

    expect(UncheckedArithmeticPlugin.scan(code)).toHaveLength(0);
  });

  it("does not treat return arrows or unary minus as arithmetic", () => {
    const code = `
      fn value(env: Env, user: Address) -> i128 {
        let amount: i128 = get(env, &user);
        amount
      }
    `;

    expect(UncheckedArithmeticPlugin.scan(code)).toHaveLength(0);
  });

  it("does not flag comments containing arithmetic text", () => {
    const code = `
      fn value(env: Env, user: Address) -> i128 {
        // balance = balance - amount with no checks
        // total * share would overflow here
        get(env, &user)
      }
    `;

    expect(UncheckedArithmeticPlugin.scan(code)).toHaveLength(0);
  });

  it("provides expression-level operator column when AST coordinates are present", () => {
    const code = [
      "fn withdraw(env: Env, user: Address, amount: i128) {", // 1
      "  let mut balance = 100;",                              // 2
      "  balance = balance - amount;",                         // 3
      "}",                                                     // 4
    ].join("\n");
    const findings = new AuditEngine(createDefaultRegistry()).run(code);
    const arithFinding = findings.find((f) => f.id === "AP-ARITH-001");

    expect(arithFinding).toBeDefined();
    expect(arithFinding?.location.function).toBe("withdraw");
    expect(arithFinding?.location.line).toBe(3);
    expect(arithFinding?.location.column).toBe(21);
  });
});

describe("UnvalidatedExternalCallPlugin (AP-CALL-001)", () => {
  it("detects token transfer with no auth or validation boundary", () => {
    const code = `
      fn payout(env: Env, token: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
      }
    `;

    const findings = UnvalidatedExternalCallPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expectWellFormedFinding(findings[0]!, "AP-CALL-001");
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.confidence).toBe("low");
    expect(findings[0]?.location.function).toBe("payout");
    expect(findings[0]?.remediation).toContain("require_auth");
  });

  it("ignores calls guarded by require_auth", () => {
    const code = `
      fn payout(env: Env, token: Address, to: Address, amount: i128) {
        env.require_auth(&to);
        let client = token::Client::new(&env, &token);
        client.transfer(&env.current_contract_address(), &to, &amount);
      }
    `;

    expect(UnvalidatedExternalCallPlugin.scan(code)).toHaveLength(0);
  });

  it("ignores calls carrying an explicitly checked token id", () => {
    // AP-008: validation is judged positionally and by evidence, not by the
    // bare presence of an `*_id` name. A checked id before the call is a
    // boundary; an unchecked one is reported at medium confidence.
    const checked = `
      fn sweep(env: Env, token_id: Address, to: Address, amount: i128) {
        assert!(token_id == &expected_token);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
      }
    `;
    const unchecked = `
      fn sweep(env: Env, token_id: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
      }
    `;

    expect(UnvalidatedExternalCallPlugin.scan(checked)).toHaveLength(0);
    const findings = UnvalidatedExternalCallPlugin.scan(unchecked);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.confidence).toBe("medium");
  });

  it("ignores ordinary functions without external calls", () => {
    const code = `
      fn name(env: Env) -> String {
        env.storage().instance().get(&NAME).unwrap_or_default()
      }
    `;

    expect(UnvalidatedExternalCallPlugin.scan(code)).toHaveLength(0);
  });

  it("does not flag commented-out transfers", () => {
    const code = `
      // client.transfer(&to, &amount);
      // token::Client::new(&env, &token);
    `;

    expect(UnvalidatedExternalCallPlugin.scan(code)).toHaveLength(0);
  });
});

describe("UnprotectedUpgradePlugin (AP-UPG-001)", () => {
  it("detects an upgrade function with no authorization check", () => {
    const code = `
      fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.storage().instance().set(&KEY_WASM, &new_wasm_hash);
      }
    `;

    const findings = UnprotectedUpgradePlugin.scan(code);

    expect(findings).toHaveLength(1);
    expectWellFormedFinding(findings[0]!, "AP-UPG-001");
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.confidence).toBe("medium");
    expect(findings[0]?.location.function).toBe("upgrade");
    expect(findings[0]?.remediation).toContain("require_auth(&admin)");
  });

  it("detects admin reassignment without require_auth", () => {
    const code = `
      fn set_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&KEY_ADMIN, &new_admin);
      }
    `;

    const findings = UnprotectedUpgradePlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("set_admin");
  });

  it("reports multiple unprotected admin functions independently", () => {
    const code = `
      fn upgrade(env: Env, wasm: BytesN<32>) {
        env.storage().instance().set(&KEY_WASM, &wasm);
      }

      fn migrate(env: Env) {
        env.storage().instance().set(&KEY_MIGRATED, &true);
      }

      fn set_fee(env: Env, fee: u32) {
        let admin: Address = env.storage().instance().get(&KEY_ADMIN).unwrap();
        env.require_auth(&admin);
        env.storage().instance().set(&KEY_FEE, &fee);
      }
    `;

    const findings = UnprotectedUpgradePlugin.scan(code);

    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.location.function)).toEqual([
      "upgrade",
      "migrate",
    ]);
  });

  it("ignores upgrade functions gated by require_auth", () => {
    const code = `
      fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&KEY_ADMIN).unwrap();
        env.require_auth(&admin);
        env.storage().instance().set(&KEY_WASM, &new_wasm_hash);
      }
    `;

    expect(UnprotectedUpgradePlugin.scan(code)).toHaveLength(0);
  });

  it("ignores ordinary state-changing functions", () => {
    const code = `
      fn record(env: Env, value: i128) {
        env.storage().instance().set(&KEY_LAST, &value);
      }
    `;

    expect(UnprotectedUpgradePlugin.scan(code)).toHaveLength(0);
  });

  it("flags set_fee when it lacks an admin check", () => {
    const code = `
      fn set_fee(env: Env, fee: u32) {
        env.storage().instance().set(&KEY_FEE, &fee);
      }
    `;

    const findings = UnprotectedUpgradePlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("set_fee");
  });
});

describe("DebugStatementsPlugin (AP-DEBUG-001)", () => {
  it("detects log!, dbg! and println! macros with distinct lines", () => {
    const code = `
      fn a(env: Env) {
        log!(env, "hello");
      }
      fn b(v: i128) {
        dbg!(v);
      }
      fn c() {
        println!("bye");
      }
    `;

    const findings = DebugStatementsPlugin.scan(code);

    expect(findings).toHaveLength(3);
    expectWellFormedFinding(findings[0]!, "AP-DEBUG-001");
    expect(findings[0]?.severity).toBe("low");
    expect(findings[0]?.confidence).toBe("high");
    expect(findings[0]?.location.line).toBe(3);
    expect(findings[1]?.location.line).toBe(6);
    expect(findings[2]?.location.line).toBe(9);
    expect(findings[0]?.message).toContain("log!");
    expect(findings[1]?.message).toContain("dbg!");
    expect(findings[2]?.message).toContain("println!");
  });

  it("ignores macros inside strings and comments", () => {
    const code = `
      fn a(env: Env) {
        let tag = "log! this"; // comment mentions dbg! too
        /* block with println! inside */
        env.storage().instance().set(&K, &tag);
      }
    `;

    expect(DebugStatementsPlugin.scan(code)).toHaveLength(0);
  });

  it("ignores non-debug macros with similar names", () => {
    const code = `
      fn a(env: Env) {
        assert!(cond);
        vec![&env];
        format!("x");
      }
    `;

    expect(DebugStatementsPlugin.scan(code)).toHaveLength(0);
  });

  it("ignores empty and non-Rust input", () => {
    expect(DebugStatementsPlugin.scan("")).toHaveLength(0);
    expect(DebugStatementsPlugin.scan("plain text")).toHaveLength(0);
  });
});

describe("finding location precision", () => {
  it("anchors AP-AUTH-001 to the fn keyword with a column when the AST is available", () => {
    const code = [
      "impl Vault {", // 1
      "  #[contractimpl]", // 2: attributes must not shift the location
      "  pub fn payout(env: Env, to: Address, amount: i128) {", // 3
      "    let client = token::Client::new(&env, &token);",
      "    client.transfer(&to, &amount);",
      "  }",
      "}",
    ].join("\n");

    // The engine feeds AST-extracted structure to function rules; a rule's
    // standalone scan() is the text-only fallback.
    const engine = new AuditEngine(createDefaultRegistry());
    const findings = engine.run(code).filter((f) => f.id === "AP-AUTH-001");

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location).toEqual({
      line: 3,
      column: 7,
      function: "payout",
    });
  });

  it("keeps AP-UPG-001 function locations without inventing columns on malformed input", () => {
    // Malformed source: extraction falls back to text, where no column is
    // known and none may be fabricated.
    const code = [
      "impl Vault {", // 1: unclosed brace, tree has errors
      "  fn upgrade(env: Env) { env.storage().set(&K, &v); }", // 2
    ].join("\n");

    const findings = UnprotectedUpgradePlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.line).toBe(2);
    expect(findings[0]?.location.column).toBeUndefined();
    expect(findings[0]?.location.function).toBe("upgrade");
  });

  it("whole-file rules attach the enclosing function and fn column per finding", () => {
    const code = [
      "impl Vault {", // 1
      "  fn balance(env: Env) -> i128 {", // 2
      "    env.storage().persistent().get(&K).unwrap()", // 3
      "  }", // 4
      "", // 5
      "  fn noisy(env: Env) {", // 6
      "    dbg!(env);", // 7
      "    env.storage().persistent().set(&K, &1);", // 8
      "  }", // 9
      "}", // 10
    ].join("\n");

    const engine = new AuditEngine(createDefaultRegistry());
    const of = (id: string) => engine.run(code).filter((f) => f.id === id);

    const error = of("AP-ERROR-001");
    expect(error).toHaveLength(1);
    expect(error[0]?.location).toEqual({ line: 3, column: 3, function: "balance" });

    const debug = of("AP-DEBUG-001");
    expect(debug).toHaveLength(1);
    expect(debug[0]?.location).toEqual({ line: 7, column: 3, function: "noisy" });

    // File-level TTL finding points at the first storage access, inside
    // `balance`.
    const storage = of("AP-STORAGE-001");
    expect(storage).toHaveLength(1);
    expect(storage[0]?.location).toEqual({ line: 3, column: 3, function: "balance" });
  });

  it("whole-file rules report line-only locations when the AST is unavailable", () => {
    // The engine passes null on malformed input; scan() is the standalone
    // text path. Either way no column or function may be fabricated.
    const code = "fn broken( {\n  let x = opt.unwrap();\n";

    const findings = UnwrapUsagePlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location).toEqual({ line: 2 });
  });
});
