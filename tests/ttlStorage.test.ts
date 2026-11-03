import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import type { Vulnerability } from "../src/types";

const FIXTURES_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "fixtures",
);

function scanFixture(relPath: string): Vulnerability[] {
  const code = fs.readFileSync(path.join(FIXTURES_ROOT, relPath), "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function idsOf(findings: Vulnerability[]): string[] {
  return findings.map((f) => f.id).sort();
}

// Issue #3: edge-case fixtures for TTL and storage expirations.
// AP-STORAGE-001 is a file-level rule — one finding when a file touches
// storage without any TTL extension, and silence as soon as any accepted
// extension form appears in the file. The fixtures therefore keep the
// unmanaged, managed, and threshold-only shapes in separate files.
describe("TTL and storage expiration fixtures (issue #3)", () => {
  it("ttl_unmanaged.rs triggers AP-STORAGE-001 exactly once and nothing else", () => {
    const findings = scanFixture("vulnerable/ttl_unmanaged.rs");
    const ttl = findings.filter((f) => f.id === "AP-STORAGE-001");

    expect(ttl).toHaveLength(1);
    expect(idsOf(findings)).toEqual(["AP-STORAGE-001"]);
    // The single file-level finding points at the first storage access.
    expect(ttl[0]?.location.function).toBe("store_balance");
  });

  it("ttl_managed.rs produces no findings", () => {
    expect(scanFixture("safe/ttl_managed.rs")).toEqual([]);
  });

  it("ttl_threshold_only.rs produces no findings", () => {
    expect(scanFixture("edge-cases/ttl_threshold_only.rs")).toEqual([]);
  });
});
