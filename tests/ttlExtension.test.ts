import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import type { Vulnerability } from "../src/types";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONTRACTS = path.join(ROOT, "contracts");

/** Scan a contract under contracts/ with the full default rule set. */
function scanContract(rel: string): Vulnerability[] {
  const code = fs.readFileSync(path.join(CONTRACTS, rel), "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

const storage = (findings: Vulnerability[]) => findings.filter((f) => f.id === "AP-STORAGE-001");

describe("contracts: TTL edge-case fixtures (temporary vs. persistent storage)", () => {
  describe("ttlMissingExtension.rs — unmanaged storage", () => {
    it("flags exactly one AP-STORAGE-001 finding at the first storage access", () => {
      const findings = scanContract("ttlMissingExtension.rs");

      expect(storage(findings)).toHaveLength(1);
      const finding = storage(findings)[0]!;
      expect(finding.severity).toBe("high");
      expect(finding.confidence).toBe("medium");
      expect(finding.location.line).toBe(34);
      expect(finding.location.function).toBe("save_persistent");
      expect(finding.location.column).toBe(9);
      expect(finding.message).toContain("extend_ttl");
      expect(finding.remediation).toContain("extend_ttl");
    });

    it("isolates the TTL rule: every other rule stays silent", () => {
      const findings = scanContract("ttlMissingExtension.rs");
      const ids = findings.map((f) => f.id);

      expect(ids).toEqual(["AP-STORAGE-001"]);
      expect(ids).not.toContain("AP-AUTH-001");
      expect(ids).not.toContain("AP-ERROR-001");
      expect(ids).not.toContain("AP-ARITH-001");
      expect(ids).not.toContain("AP-CALL-001");
      expect(ids).not.toContain("AP-UPG-001");
      expect(ids).not.toContain("AP-DEBUG-001");
    });

    it("reports the finding only once despite six storage accesses", () => {
      const code = fs.readFileSync(path.join(CONTRACTS, "ttlMissingExtension.rs"), "utf-8");
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(1);
    });

    it("does not treat a line-commented extend_ttl as extension", () => {
      const code = `
        fn save(env: Env, key: Symbol, value: i128) {
          env.storage().persistent().set(&key, &value);
          // env.storage().persistent().extend_ttl(&key, 100, 200);
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(1);
    });

    it("does not treat a block-commented extend_ttl as extension", () => {
      const code = `
        fn save(env: Env, key: Symbol, value: i128) {
          env.storage().persistent().set(&key, &value);
          /* env.storage().persistent().extend_ttl(&key, 100, 200); */
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(1);
    });

    it("does not treat a bare extend_ttl mention in a doc string as extension", () => {
      const code = `
        fn save(env: Env, key: Symbol, value: i128) {
          env.storage().persistent().set(&key, &value);
          let doc = "call extend_ttl(&key, 100, 200) to keep this entry alive";
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(1);
    });

    it("stays silent when no storage is accessed at all", () => {
      expect(MissingExtendTtlPlugin.scan("fn add(a: i128, b: i128) -> i128 { a + b }")).toHaveLength(0);
    });
  });

  describe("ttlManagedExtension.rs — extended storage", () => {
    it("produces zero findings across the full default rule set", () => {
      expect(scanContract("ttlManagedExtension.rs")).toEqual([]);
    });

    it("recognizes persistent extend_ttl as extension", () => {
      const code = `
        fn save(env: Env, key: Symbol, value: i128) {
          env.storage().persistent().set(&key, &value);
          env.storage().persistent().extend_ttl(&key, 100, 200);
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
    });

    it("recognizes temporary extend_ttl_to_threshold as extension", () => {
      const code = `
        fn save(env: Env, key: Symbol, value: i128) {
          env.storage().temporary().set(&key, &value);
          env.storage().temporary().extend_ttl_to_threshold(&key, 50);
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
    });

    it("recognizes instance extend_ttl_to_threshold as extension", () => {
      const code = `
        fn save(env: Env, key: Symbol, value: i128) {
          env.storage().instance().set(&key, &value);
          env.storage().instance().extend_ttl_to_threshold(&key, 100);
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
    });

    it("recognizes instance extend_ttl as extension", () => {
      const code = `
        fn bump(env: Env, key: Symbol) {
          env.storage().instance().extend_ttl(&key, 100, 200);
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
    });

    it("recognizes get_extended as extension", () => {
      const code = `
        fn load(env: Env, key: Symbol) -> i128 {
          env.storage().persistent().get_extended(&key).unwrap_or_default()
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
    });

    it("silences the whole file when one extension call is present", () => {
      const code = `
        fn save(env: Env, key: Symbol, value: i128) {
          env.storage().persistent().set(&key, &value);
        }
        fn bump(env: Env, key: Symbol) {
          env.storage().persistent().extend_ttl(&key, 100, 200);
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
    });

    it("silences even when the extension is split across lines", () => {
      const code = `
        fn save(env: Env, key: Symbol, value: i128) {
          env.storage().persistent().set(&key, &value);
          env.storage()
            .persistent()
            .extend_ttl(&key, 100, 200);
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
    });
  });

  describe("location precision on the vulnerable contract", () => {
    it("anchors the finding at the first storage access with the enclosing function", () => {
      const code = fs.readFileSync(path.join(CONTRACTS, "ttlMissingExtension.rs"), "utf-8");
      const findings = new AuditEngine(createDefaultRegistry()).run(code);

      expect(findings).toHaveLength(1);
      expect(findings[0]?.location).toEqual({
        line: 34,
        column: 9,
        function: "save_persistent",
      });
    });
  });
});
