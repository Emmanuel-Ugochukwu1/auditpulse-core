import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import type { Vulnerability } from "../src/types";

/**
 * Issue #2 — detection across complex Soroban macro expansions.
 *
 * contract: contracts/ttl_macro_expansion.rs
 *
 * Verifies the Missing-Extend-TTL rule (`AP-STORAGE-001`) does NOT false-positive
 * when the TTL bump is hidden inside `macro_rules!` helper / macro expansions.
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

function idsOf(findings: Vulnerability[]): string[] {
  return findings.map((f) => f.id).sort();
}

describe("issue #2 — detection across complex Soroban macro expansions (contracts/ttl_macro_expansion.rs)", () => {
  it("does NOT false-positive when the TTL bump is hidden inside a macro", () => {
    const findings = scanContract("ttl_macro_expansion.rs");

    // The storage read happens inside a macro_rules! helper, but the same path
    // correctly calls extend_ttl_to_threshold, so the rule must stay silent.
    expect(idsOf(findings)).not.toContain("AP-STORAGE-001");
  });
});
