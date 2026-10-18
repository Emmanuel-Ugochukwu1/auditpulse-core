/**
 * Regression tests for the AP-STORAGE-001 fixture pair shipped in #3.
 *
 * The two `.rs` files are read straight from `contracts/` and handed to
 * the engine so the tests run in a worker without touching
 * `process.chdir()` (the surrounding integration suite relies on cwd
 * mutations which are unavailable inside vitest's worker context).
 *
 * The vulnerable fixture is expected to produce AP-STORAGE-001 plus the
 * related findings it deliberately embeds; the managed counterpart must
 * scan clean across the same public surface.
 */

import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import type { Vulnerability } from "../src/types";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.join(__dirname, "..");
const CONTRACTS_DIR = path.join(REPO_ROOT, "contracts");

function scanFixture(filename: string): Vulnerability[] {
  const code = fs.readFileSync(path.join(CONTRACTS_DIR, filename), "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function idsOf(findings: Vulnerability[]): string[] {
  return Array.from(new Set(findings.map((f) => f.id))).sort();
}

describe("contracts/TtlEdgeCaseMatrix.rs (#3 vulnerable fixture)", () => {
  const findings = scanFixture("TtlEdgeCaseMatrix.rs");

  it("flags the file-level AP-STORAGE-001 finding", () => {
    const storage = findings.filter((f) => f.id === "AP-STORAGE-001");
    // The rule is file-level: exactly one finding for the whole file.
    expect(storage).toHaveLength(1);
    expect(storage[0]?.severity).toBe("high");
    expect(storage[0]?.message.toLowerCase()).toContain("extend_ttl");
  });

  it("flags the AP-ERROR-001 from the storage read", () => {
    const unwraps = findings.filter((f) => f.id === "AP-ERROR-001");
    expect(unwraps.length).toBeGreaterThanOrEqual(1);
  });

  it("flags AP-AUTH-001 on the storage-mutating writers", () => {
    const auth = findings.filter((f) => f.id === "AP-AUTH-001");
    // store_persistent + store_instance + store_with_shadowed_extend +
    // store_with_conditional_extend are the four writers missing auth.
    expect(auth.length).toBeGreaterThanOrEqual(3);
  });

  it("reports findings from every documented vulnerable surface", () => {
    // Sanity: the fixture deliberately triggers at least these three ids.
    expect(idsOf(findings)).toEqual(
      expect.arrayContaining([
        "AP-AUTH-001",
        "AP-STORAGE-001",
        "AP-ERROR-001",
      ]),
    );
  });
});

describe("contracts/TtlEdgeCaseManaged.rs (#3 managed counterpart)", () => {
  const findings = scanFixture("TtlEdgeCaseManaged.rs");

  it("produces no AP-STORAGE-001 finding", () => {
    expect(findings.filter((f) => f.id === "AP-STORAGE-001")).toHaveLength(0);
  });

  it("produces no AP-AUTH-001 finding", () => {
    expect(findings.filter((f) => f.id === "AP-AUTH-001")).toHaveLength(0);
  });

  it("produces no AP-ERROR-001 finding", () => {
    expect(findings.filter((f) => f.id === "AP-ERROR-001")).toHaveLength(0);
  });

  it("scans entirely clean", () => {
    expect(findings).toHaveLength(0);
  });
});

describe("AP-STORAGE-001 file-level rule regression", () => {
  it("fires even when an extend_ttl call exists inside a // line comment", () => {
    // Verifies the rule strips comments before evaluating the file:
    // removeComments turns the second line into whitespace, leaving no
    // surviving extend_ttl call in the source the rule sees.
    const code = [
      "fn shadow(env: Env) {",
      "  // env.storage().persistent().extend_ttl(&k, 100, 200);",
      "  env.storage().persistent().set(&k, &1);",
      "}",
    ].join("\n");
    const engine = new AuditEngine(createDefaultRegistry());
    const findings = engine.run(code);
    expect(findings.some((f) => f.id === "AP-STORAGE-001")).toBe(true);
  });

  it("does not fire when an unconditional extend_ttl call exists", () => {
    const code = [
      "fn safe(env: Env) {",
      "  env.storage().persistent().set(&k, &1);",
      "  env.storage().persistent().extend_ttl(&k, 100, 200);",
      "}",
    ].join("\n");
    const engine = new AuditEngine(createDefaultRegistry());
    const findings = engine.run(code);
    expect(findings.some((f) => f.id === "AP-STORAGE-001")).toBe(false);
  });
});