import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import type { Vulnerability } from "../src/types";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const UNMANAGED = path.join(ROOT, "contracts", "TtlStorageTiers.rs");
const MANAGED = path.join(ROOT, "contracts", "TtlStorageTiersManaged.rs");

function scanFile(filePath: string): Vulnerability[] {
  const code = fs.readFileSync(filePath, "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function idsOf(findings: Vulnerability[]): string[] {
  return findings.map((f) => f.id).sort();
}

describe("TTL storage tier fixtures (#3)", () => {
  it("ships unmanaged + managed contracts under contracts/", () => {
    expect(fs.existsSync(UNMANAGED)).toBe(true);
    expect(fs.existsSync(MANAGED)).toBe(true);
    const unmanaged = fs.readFileSync(UNMANAGED, "utf-8");
    const managed = fs.readFileSync(MANAGED, "utf-8");
    expect(unmanaged).toMatch(/storage\s*\(\s*\)\s*\.\s*persistent/);
    expect(unmanaged).toMatch(/storage\s*\(\s*\)\s*\.\s*temporary/);
    expect(unmanaged).not.toMatch(/\.extend_ttl\s*\(/);
    expect(managed).toMatch(/\.extend_ttl\s*\(/);
    expect(managed).toMatch(/require_auth/);
  });

  it("flags AP-STORAGE-001 on unmanaged temporary+persistent tiers", () => {
    const findings = scanFile(UNMANAGED);
    const storage = findings.filter((f) => f.id === "AP-STORAGE-001");
    expect(storage.length).toBeGreaterThan(0);
    expect(storage[0]?.message.toLowerCase()).toMatch(/extend_ttl|ttl|expir/);
  });

  it("stays quiet on AP-STORAGE-001 for managed tiers", () => {
    const findings = scanFile(MANAGED);
    expect(idsOf(findings)).not.toContain("AP-STORAGE-001");
  });
});
