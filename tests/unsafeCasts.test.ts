import { describe, it, expect } from "vitest";
import UnsafeCastsPlugin from "../src/plugins/unsafeCasts";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";

describe("AP-CAST-001 (UnsafeCastsPlugin)", () => {
  it("flags narrowing integer casts on amount-like values", () => {
    const code = `
      fn process_fee(env: Env, fee: i128) {
        let small_fee = fee as u64;
      }

      fn convert_balance(env: Env, balance: u128) {
        let compact_bal = balance as u32;
      }
    `;

    const findings = UnsafeCastsPlugin.scan(code);
    expect(findings).toHaveLength(2);

    expect(findings[0]?.id).toBe("AP-CAST-001");
    expect(findings[0]?.severity).toBe("medium");
    expect(findings[0]?.confidence).toBe("medium");
    expect(findings[0]?.location.function).toBe("process_fee");
    expect(findings[0]?.location.line).toBe(3);
    expect(findings[0]?.remediation).toContain("try_from");

    expect(findings[1]?.id).toBe("AP-CAST-001");
    expect(findings[1]?.location.function).toBe("convert_balance");
    expect(findings[1]?.location.line).toBe(7);
  });

  it("ignores safe conversion patterns like try_into and try_from", () => {
    const code = `
      fn process_safely(env: Env, fee: i128) {
        let small_fee = u64::try_from(fee).unwrap_or(0);
        let checked_bal: Result<u32, _> = balance.try_into();
      }
    `;

    const findings = UnsafeCastsPlugin.scan(code);
    expect(findings).toHaveLength(0);
  });

  it("ignores non-amount identifier casts", () => {
    const code = `
      fn iterate(env: Env, count: u128) {
        let idx = count as usize;
        let offset = step as u32;
      }
    `;

    const findings = UnsafeCastsPlugin.scan(code);
    expect(findings).toHaveLength(0);
  });

  it("respects disabled_rules configuration via AuditEngine", () => {
    const code = `
      fn pay(env: Env, amount: i128) {
        let truncated = amount as u64;
      }
    `;

    const engine = new AuditEngine(createDefaultRegistry());
    const findingsActive = engine.run(code, { disabledRules: [] });
    expect(findingsActive.some((f) => f.id === "AP-CAST-001")).toBe(true);

    const findingsDisabled = engine.run(code, { disabledRules: ["AP-CAST-001"] });
    expect(findingsDisabled.some((f) => f.id === "AP-CAST-001")).toBe(false);
  });
});
