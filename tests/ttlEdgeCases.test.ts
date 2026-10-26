import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import type { Vulnerability } from "../src/types";

const CONTRACTS_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
);

function scanContract(filename: string): Vulnerability[] {
  const code = fs.readFileSync(path.join(CONTRACTS_ROOT, filename), "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function storageFindings(findings: Vulnerability[]): Vulnerability[] {
  return findings.filter((f) => f.id === "AP-STORAGE-001");
}

describe("contracts/TtlEdgeCases.rs", () => {
  it("flags temp_missing_ttl for unextended temporary storage", () => {
    const findings = storageFindings(scanContract("TtlEdgeCases.rs"));
    const funcs = findings.map((f) => f.location.function);

    expect(funcs).toContain("temp_missing_ttl");
  });

  it("flags persistent_missing for unextended persistent storage", () => {
    const findings = storageFindings(scanContract("TtlEdgeCases.rs"));
    const funcs = findings.map((f) => f.location.function);

    expect(funcs).toContain("persistent_missing");
  });

  it("does not flag temp_with_ttl or persistent_with_ttl", () => {
    const findings = storageFindings(scanContract("TtlEdgeCases.rs"));
    const funcs = findings.map((f) => f.location.function);

    expect(funcs).not.toContain("temp_with_ttl");
    expect(funcs).not.toContain("persistent_with_ttl");
  });

  it("does not flag zero_threshold_ttl — extend_ttl is called", () => {
    const findings = storageFindings(scanContract("TtlEdgeCases.rs"));
    const funcs = findings.map((f) => f.location.function);

    expect(funcs).not.toContain("zero_threshold_ttl");
  });

  it("does not flag temp_read_only — reads do not need TTL extension", () => {
    const findings = storageFindings(scanContract("TtlEdgeCases.rs"));
    const funcs = findings.map((f) => f.location.function);

    expect(funcs).not.toContain("temp_read_only");
  });

  it("flags mixed_lifetimes for the unextended persistent entry", () => {
    const findings = storageFindings(scanContract("TtlEdgeCases.rs"));
    const funcs = findings.map((f) => f.location.function);

    expect(funcs).toContain("mixed_lifetimes");
  });

  it("produces exactly the expected set of storage findings", () => {
    const findings = storageFindings(scanContract("TtlEdgeCases.rs"));
    const funcs = findings.map((f) => f.location.function).sort();

    expect(funcs).toEqual([
      "mixed_lifetimes",
      "persistent_missing",
      "temp_missing_ttl",
    ]);
  });
});
