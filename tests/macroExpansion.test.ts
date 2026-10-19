import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import MissingRequireAuthPlugin from "../src/plugins/missingRequireAuth";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import UnprotectedUpgradePlugin from "../src/plugins/unprotectedUpgrade";
import { scanTarget } from "../src/scanner";
import { defaultConfig } from "../src/config";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

function engine(): AuditEngine {
  return new AuditEngine(createDefaultRegistry());
}

describe("Macro expansion and storage TTL detection (Issue #2)", () => {
  const contractPath = path.join(ROOT, "contracts", "MacroExpandedVault.rs");

  it("accurately detects vulnerabilities in contracts using complex macro expansions", () => {
    const code = fs.readFileSync(contractPath, "utf-8");
    const findings = engine().run(code);

    // unprotected_withdraw must be flagged for missing auth
    const authFindings = findings.filter((f) => f.id === "AP-AUTH-001");
    expect(authFindings).toHaveLength(1);
    expect(authFindings[0]?.location.function).toBe("unprotected_withdraw");

    // deposit, create_session, refresh_state and upgrade use macro-based guards and must not be flagged
    expect(findings.some((f) => f.location.function === "deposit")).toBe(false);
    expect(findings.some((f) => f.location.function === "create_session")).toBe(false);
    expect(findings.some((f) => f.location.function === "refresh_state")).toBe(false);
    expect(findings.some((f) => f.location.function === "upgrade")).toBe(false);

    // AP-STORAGE-001 must not fire because extend_*_ttl! macros extend storage TTLs
    expect(findings.filter((f) => f.id === "AP-STORAGE-001")).toHaveLength(0);
  });

  it("recognizes require_auth! and require_auth_for_args! macro invocations in MissingRequireAuthPlugin", () => {
    const safeMacroAuth = `
      fn transfer_funds(env: Env, from: Address, to: Address, amount: i128) {
        require_auth!(from);
        client.transfer(&from, &to, &amount);
      }
    `;
    expect(MissingRequireAuthPlugin.scan(safeMacroAuth)).toHaveLength(0);

    const safeMacroForArgs = `
      fn transfer_funds(env: Env, from: Address, to: Address, amount: i128) {
        require_auth_for_args!(from, (amount,));
        client.transfer(&from, &to, &amount);
      }
    `;
    expect(MissingRequireAuthPlugin.scan(safeMacroForArgs)).toHaveLength(0);

    const safeBraceMacro = `
      fn transfer_funds(env: Env, from: Address, to: Address, amount: i128) {
        require_auth!{from};
        client.transfer(&from, &to, &amount);
      }
    `;
    expect(MissingRequireAuthPlugin.scan(safeBraceMacro)).toHaveLength(0);
  });

  it("recognizes extend_ttl macro invocations across storage tiers in MissingExtendTtlPlugin", () => {
    const safePersistentMacro = `
      fn save_persistent(env: Env, key: Symbol, val: i128) {
        env.storage().persistent().set(&key, &val);
        extend_persistent_ttl!(env, key, 100, 200);
      }
    `;
    expect(MissingExtendTtlPlugin.scan(safePersistentMacro)).toHaveLength(0);

    const safeTemporaryMacro = `
      fn save_temporary(env: Env, key: Symbol, val: i128) {
        env.storage().temporary().set(&key, &val);
        extend_temporary_ttl!(env, key, 100, 200);
      }
    `;
    expect(MissingExtendTtlPlugin.scan(safeTemporaryMacro)).toHaveLength(0);

    const safeBumpMacro = `
      fn bump_entry(env: Env, key: Symbol) {
        env.storage().temporary().set(&key, &1);
        bump_ttl!(env, key);
      }
    `;
    expect(MissingExtendTtlPlugin.scan(safeBumpMacro)).toHaveLength(0);

    const safeThresholdMacro = `
      fn save_threshold(env: Env, key: Symbol, val: i128) {
        env.storage().persistent().set(&key, &val);
        extend_ttl_to_threshold!(env.storage().persistent(), key, 100, 200);
      }
    `;
    expect(MissingExtendTtlPlugin.scan(safeThresholdMacro)).toHaveLength(0);
  });

  it("flags unextended temporary storage access when TTL extensions are omitted", () => {
    const unextendedTemporary = `
      fn cache_value(env: Env, key: Symbol, val: i128) {
        env.storage().temporary().set(&key, &val);
      }
    `;
    const findings = MissingExtendTtlPlugin.scan(unextendedTemporary);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-STORAGE-001");
  });

  it("flags unextended persistent storage access when TTL extensions are omitted", () => {
    const unextendedPersistent = `
      fn store_balance(env: Env, key: Symbol, val: i128) {
        env.storage().persistent().set(&key, &val);
      }
    `;
    const findings = MissingExtendTtlPlugin.scan(unextendedPersistent);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-STORAGE-001");
  });

  it("recognizes macro-gated administrative entrypoints in UnprotectedUpgradePlugin", () => {
    const safeUpgradeMacro = `
      fn upgrade(env: Env, admin: Address, hash: BytesN<32>) {
        require_auth!(admin);
        env.deployer().update_current_contract_wasm(hash);
      }
    `;
    expect(UnprotectedUpgradePlugin.scan(safeUpgradeMacro)).toHaveLength(0);

    const unprotectUpgrade = `
      fn upgrade(env: Env, admin: Address, hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(hash);
      }
    `;
    expect(UnprotectedUpgradePlugin.scan(unprotectUpgrade)).toHaveLength(1);
  });

  it("verifies CLI scanner execution against MacroExpandedVault.rs", () => {
    const report = scanTarget(contractPath, engine(), defaultConfig());
    expect(report.filesScanned).toBe(1);
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.some((f) => f.id === "AP-AUTH-001")).toBe(true);
    expect(
      report.findings.find((f) => f.id === "AP-AUTH-001")?.location.function,
    ).toBe("unprotected_withdraw");
  });
});
