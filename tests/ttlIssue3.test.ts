import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import type { Vulnerability } from "../src/types";

// Issue #3 — temporary vs. persistent storage, no TTL bump.
const CONTRACTS_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
);

function scanContract(relPath: string): Vulnerability[] {
  const code = fs.readFileSync(path.join(CONTRACTS_ROOT, relPath), "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

describe("issue #3 — contracts/ttl_temporary_vs_persistent.rs", () => {
  it("flags the contract when both storage tiers are left un-extended", () => {
    const findings = scanContract("ttl_temporary_vs_persistent.rs");

    // The contract touches persistent(), temporary() and instance() storage but
    // never calls extend_ttl / extend_ttl_to_threshold / get_extended, so the
    // missing-TTL rule must fire.
    expect(findings.filter((f) => f.id === "AP-STORAGE-001").length).toBeGreaterThan(0);
  });
});
