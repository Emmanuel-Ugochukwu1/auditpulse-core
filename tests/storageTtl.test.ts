import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { scanTarget } from "../src/scanner";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { defaultConfig } from "../src/config";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";

describe("Storage TTL extensions (contracts/StorageTtlVault.rs and edge cases)", () => {
  it("scans contracts/StorageTtlVault.rs with zero AP-STORAGE-001 findings", () => {
    const vaultPath = resolve("contracts/StorageTtlVault.rs");
    const engine = new AuditEngine(createDefaultRegistry());
    const report = scanTarget(vaultPath, engine, defaultConfig());

    const storageFindings = report.findings.filter((f) => f.id === "AP-STORAGE-001");
    expect(storageFindings).toHaveLength(0);
    expect(report.findings).toHaveLength(0);
  });

  it("handles temporary storage with extend_ttl_to_threshold properly", () => {
    const code = `
      fn cache_session(env: Env, session: Address, token: i128) {
        env.storage().temporary().set(&session, &token);
        env.storage().temporary().extend_ttl_to_threshold(&session, 100, 500);
      }
    `;
    const findings = MissingExtendTtlPlugin.scan(code);
    expect(findings).toHaveLength(0);
  });

  it("flags persistent storage access when extend_ttl is omitted", () => {
    const code = `
      fn write_without_bump(env: Env, key: Symbol, value: i128) {
        env.storage().persistent().set(&key, &value);
      }
    `;
    const findings = MissingExtendTtlPlugin.scan(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-STORAGE-001");
    expect(findings[0]?.message).toContain("extend_ttl");
  });

  it("flags temporary storage access when TTL extension is omitted", () => {
    const code = `
      fn temp_without_bump(env: Env, key: Symbol, value: i128) {
        env.storage().temporary().set(&key, &value);
      }
    `;
    const findings = MissingExtendTtlPlugin.scan(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-STORAGE-001");
  });

  it("accepts get_extended as a valid storage TTL extension pattern", () => {
    const code = `
      fn read_and_bump(env: Env, key: Symbol) -> i128 {
        env.storage().persistent().get_extended(&key, 100, 200).unwrap_or(0)
      }
    `;
    const findings = MissingExtendTtlPlugin.scan(code);
    expect(findings).toHaveLength(0);
  });
});
