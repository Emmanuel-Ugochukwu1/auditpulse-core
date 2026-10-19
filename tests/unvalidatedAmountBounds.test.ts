import { describe, it, expect } from "vitest";
import UnvalidatedAmountBoundsPlugin from "../src/plugins/unvalidatedAmountBounds";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";

describe("AP-BOUND-001 (UnvalidatedAmountBoundsPlugin)", () => {
  it("flags unbounded entrypoints that adjust balances", () => {
    const code = `
      fn deposit(env: Env, user: Address, amount: i128) {
        let balance = env.storage().persistent().get(&user).unwrap_or(0);
        env.storage().persistent().set(&user, &(balance + amount));
      }

      fn withdraw(env: Env, user: Address, amount: i128) {
        let mut balance: i128 = get_balance(&user);
        balance = balance - amount;
        env.storage().persistent().set(&user, &balance);
      }
    `;

    const findings = UnvalidatedAmountBoundsPlugin.scan(code);
    expect(findings).toHaveLength(2);

    expect(findings[0]?.id).toBe("AP-BOUND-001");
    expect(findings[0]?.severity).toBe("low");
    expect(findings[0]?.confidence).toBe("low");
    expect(findings[0]?.location.function).toBe("deposit");
    expect(findings[0]?.location.line).toBe(2);
    expect(findings[0]?.remediation).toContain("assert!(amount > 0)");

    expect(findings[1]?.id).toBe("AP-BOUND-001");
    expect(findings[1]?.location.function).toBe("withdraw");
    expect(findings[1]?.location.line).toBe(7);
  });

  it("stays silent when entrypoints include positivity or bound checks", () => {
    const code = `
      fn deposit(env: Env, user: Address, amount: i128) {
        assert!(amount > 0, "must be positive");
        let balance = env.storage().persistent().get(&user).unwrap_or(0);
        env.storage().persistent().set(&user, &(balance + amount));
      }

      fn withdraw(env: Env, user: Address, amount: i128) {
        if amount <= 0 {
          panic!("non-positive");
        }
        let balance = env.storage().persistent().get(&user).unwrap_or(0);
        assert!(balance >= amount, "insufficient funds");
        env.storage().persistent().set(&user, &(balance - amount));
      }

      fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        require!(amount > 0, "transfer amount zero");
        env.storage().persistent().set(&from, &0);
      }
    `;

    const findings = UnvalidatedAmountBoundsPlugin.scan(code);
    expect(findings).toHaveLength(0);
  });

  it("ignores non-entrypoint names even if they mutate balances", () => {
    const code = `
      fn recalculate_pool(env: Env, shares: i128) {
        let pool = env.storage().persistent().get(&POOL).unwrap_or(0);
        env.storage().persistent().set(&POOL, &(pool + shares));
      }

      fn internal_sync_balance(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set(&user, &amount);
      }
    `;

    const findings = UnvalidatedAmountBoundsPlugin.scan(code);
    expect(findings).toHaveLength(0);
  });

  it("respects disabled_rules configuration in AuditEngine", () => {
    const code = `
      fn deposit(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set(&user, &amount);
      }
    `;

    const engine = new AuditEngine(createDefaultRegistry());
    const findingsActive = engine.run(code, { disabledRules: [] });
    expect(findingsActive.some((f) => f.id === "AP-BOUND-001")).toBe(true);

    const findingsDisabled = engine.run(code, { disabledRules: ["AP-BOUND-001"] });
    expect(findingsDisabled.some((f) => f.id === "AP-BOUND-001")).toBe(false);
  });
});
