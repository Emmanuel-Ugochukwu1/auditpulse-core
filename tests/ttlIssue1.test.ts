import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import type { Vulnerability } from "../src/types";

/**
 * Issue #1 — minimal persistent read/write with no TTL extension.
 *
 * contract: contracts/ttl_persistent_instance.rs
 *
 * Verifies the Missing-Extend-TTL rule (`AP-STORAGE-001`) behaves correctly for
 * a minimal single-tier persistent storage access that is never bumped, and
 * that every produced finding is well-formed for JSON / SARIF CI consumers.
 */

const CONTRACTS_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
);

function scanContract(relPath: string): Vulnerability[] {
  const code = fs.readFileSync(path.join(CONTRACTS_ROOT, relPath), "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

describe("issue #1 — minimal persistent read/write with no extension (contracts/ttl_persistent_instance.rs)", () => {
  const findings = scanContract("ttl_persistent_instance.rs");

  it("reports exactly one well-formed Missing-Extend-TTL finding", () => {
    const ttl = findings.filter((f) => f.id === "AP-STORAGE-001");

    expect(ttl).toHaveLength(1);
    expect(ttl[0]?.severity).toBe("high");
    expect(ttl[0]?.location.line).toBeGreaterThan(0);
    expect(ttl[0]?.remediation).toContain("extend_ttl");
  });

  it("produces valid structured output for CI/SARIF consumers", () => {
    // Every finding is well-formed so the JSON/SARIF reporters never emit
    // empty locations or messages for this scan target.
    for (const finding of findings) {
      expect(finding.id).toMatch(/^AP-[A-Z]+-\d{3}$/);
      expect(["critical", "high", "medium", "low"]).toContain(finding.severity);
      expect(finding.location.line).toBeGreaterThan(0);
      expect(finding.message.length).toBeGreaterThan(10);
      expect(finding.remediation).toBeTruthy();
    }
  });
});
