import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import { scanTarget } from "../src/scanner";
import { defaultConfig } from "../src/config";
import type { Vulnerability } from "../src/types";

const CONTRACTS_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
);

function readContract(fileName: string): string {
  return fs.readFileSync(path.join(CONTRACTS_ROOT, fileName), "utf-8");
}

function scanWithEngine(code: string): Vulnerability[] {
  const engine = new AuditEngine(createDefaultRegistry());
  return engine.run(code);
}

describe("TTL edge-case fixtures: temporary vs persistent storage (Issue #3)", () => {
  const edgeCasesSource = readContract("StorageTtlEdgeCases.rs");
  const managedSource = readContract("StorageTtlManaged.rs");

  describe("StorageTtlEdgeCases.rs (unmanaged TTL & edge cases)", () => {
    it("flags unmanaged persistent and temporary storage with AP-STORAGE-001", () => {
      const findings = scanWithEngine(edgeCasesSource);
      const storageFindings = findings.filter((f) => f.id === "AP-STORAGE-001");

      expect(storageFindings).toHaveLength(1);
      const finding = storageFindings[0]!;
      expect(finding.severity).toBe("high");
      expect(finding.confidence).toBe("medium");
      expect(finding.message).toContain("extend_ttl");
      expect(finding.remediation).toContain("extend_ttl");
      expect(finding.location.function).toBe("set_balance");
    });

    it("flags dangerous .unwrap() on potentially expired storage with AP-ERROR-001", () => {
      const findings = scanWithEngine(edgeCasesSource);
      const errorFindings = findings.filter((f) => f.id === "AP-ERROR-001");

      expect(errorFindings.length).toBeGreaterThan(0);
      expect(errorFindings[0]?.location.function).toBe("get_balance");
      expect(errorFindings[0]?.message).toContain(".unwrap()");
    });

    it("flags missing require_auth on unauthorized state mutations with AP-AUTH-001", () => {
      const findings = scanWithEngine(edgeCasesSource);
      const authFindings = findings.filter((f) => f.id === "AP-AUTH-001");
      const authFunctions = authFindings.map((f) => f.location.function);

      expect(authFunctions).toContain("set_balance");
      expect(authFunctions).toContain("grant_session");
      expect(authFunctions).toContain("consume_session");
      expect(authFunctions).toContain("emergency_drain");
      // get_balance is a read-only getter, should not be flagged for auth
      expect(authFunctions).not.toContain("get_balance");
    });
  });

  describe("StorageTtlManaged.rs (managed TTL reference)", () => {
    it("produces zero AP-STORAGE-001 findings on properly extended storage", () => {
      const findings = scanWithEngine(managedSource);
      const storageFindings = findings.filter((f) => f.id === "AP-STORAGE-001");

      expect(storageFindings).toHaveLength(0);
    });

    it("scans completely clean with zero vulnerabilities across all rules", () => {
      const findings = scanWithEngine(managedSource);
      expect(findings).toHaveLength(0);
    });
  });

  describe("MissingExtendTtlPlugin edge-case unit assertions", () => {
    it("flags temporary storage access alone when un-extended", () => {
      const code = `
        impl Contract {
          pub fn store_temp(env: Env, key: Symbol, val: i128) {
            env.storage().temporary().set(&key, &val);
          }
        }
      `;
      const findings = MissingExtendTtlPlugin.scan(code);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.id).toBe("AP-STORAGE-001");
    });

    it("flags persistent storage access alone when un-extended", () => {
      const code = `
        impl Contract {
          pub fn store_persist(env: Env, key: Symbol, val: i128) {
            env.storage().persistent().set(&key, &val);
          }
        }
      `;
      const findings = MissingExtendTtlPlugin.scan(code);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.id).toBe("AP-STORAGE-001");
    });

    it("recognizes extend_ttl_to_threshold as a valid TTL extension", () => {
      const code = `
        impl Contract {
          pub fn store(env: Env, key: Symbol, val: i128) {
            env.storage().persistent().set(&key, &val);
            env.storage().persistent().extend_ttl_to_threshold(&key, 100, 200);
          }
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
    });

    it("recognizes get_extended as a valid TTL extension", () => {
      const code = `
        impl Contract {
          pub fn fetch(env: Env, key: Symbol) -> i128 {
            env.storage().persistent().get_extended(&key, 100, 200).unwrap_or(0)
          }
        }
      `;
      expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
    });
  });

  describe("CLI scan verification (acceptance criteria)", () => {
    it("scans StorageTtlManaged.rs cleanly via the scanner target runner", () => {
      const managedPath = path.join(CONTRACTS_ROOT, "StorageTtlManaged.rs");
      const engine = new AuditEngine(createDefaultRegistry());
      const report = scanTarget(managedPath, engine, defaultConfig());
      expect(report.filesScanned).toBe(1);
      expect(report.findings).toHaveLength(0);
    });

    it("scans StorageTtlEdgeCases.rs via scanner target runner and identifies AP-STORAGE-001", () => {
      const edgeCasesPath = path.join(CONTRACTS_ROOT, "StorageTtlEdgeCases.rs");
      const engine = new AuditEngine(createDefaultRegistry());
      const report = scanTarget(edgeCasesPath, engine, defaultConfig());
      expect(report.filesScanned).toBe(1);
      const storage = report.findings.filter((f) => f.id === "AP-STORAGE-001");
      expect(storage).toHaveLength(1);
      expect(storage[0]?.severity).toBe("high");
    });
  });
});


