import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { scanTarget } from "../src/scanner";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { defaultConfig } from "../src/config";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";

describe("Edge-case TTL and storage expiration test suite (#3)", () => {
  it("scans contracts/StorageExpiryVault.rs with zero security findings", () => {
    const vaultPath = resolve("contracts/StorageExpiryVault.rs");
    const engine = new AuditEngine(createDefaultRegistry());
    const report = scanTarget(vaultPath, engine, defaultConfig());

    const storageFindings = report.findings.filter((f) => f.id === "AP-STORAGE-001");
    expect(storageFindings).toHaveLength(0);
    expect(report.findings).toHaveLength(0);
  });

  describe("Temporary vs Persistent storage TTL extension edge cases", () => {
    it("safely handles temporary storage using extend_ttl_to_threshold", () => {
      const code = `
        fn cache_session(env: Env, session: Address, nonce: u64) {
          env.storage().temporary().set(&session, &nonce);
          env.storage().temporary().extend_ttl_to_threshold(&session, 100, 500);
        }
      `;
      const findings = MissingExtendTtlPlugin.scan(code);
      expect(findings).toHaveLength(0);
    });

    it("flags unextended temporary storage access risking ephemeral state loss", () => {
      const code = `
        fn store_session(env: Env, session: Address, nonce: u64) {
          env.storage().temporary().set(&session, &nonce);
        }
      `;
      const findings = MissingExtendTtlPlugin.scan(code);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.id).toBe("AP-STORAGE-001");
      expect(findings[0]?.severity).toBe("high");
      expect(findings[0]?.message).toContain("extend_ttl");
    });

    it("flags unextended persistent storage access risking silent data archiving", () => {
      const code = `
        fn save_user_profile(env: Env, user: Address, data: Symbol) {
          env.storage().persistent().set(&user, &data);
        }
      `;
      const findings = MissingExtendTtlPlugin.scan(code);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.id).toBe("AP-STORAGE-001");
      expect(findings[0]?.remediation).toContain("extend_ttl");
    });

    it("recognizes get_extended pattern as safe storage access with TTL bump", () => {
      const code = `
        fn get_cached_balance(env: Env, user: Address) -> i128 {
          env.storage().persistent().get_extended(&user, 50, 200).unwrap_or(0)
        }
      `;
      const findings = MissingExtendTtlPlugin.scan(code);
      expect(findings).toHaveLength(0);
    });

    it("ignores storage keywords inside comments", () => {
      const code = `
        // env.storage().persistent().set(&user, &data);
        /* env.storage().temporary().set(&session, &nonce); */
        fn compute(a: i128, b: i128) -> i128 {
          a + b
        }
      `;
      const findings = MissingExtendTtlPlugin.scan(code);
      expect(findings).toHaveLength(0);
    });
  });
});
