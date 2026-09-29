import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import type { Vulnerability } from "../src/types";

const CONTRACT_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
  "TtlEdgeCases.rs",
);

/** 1-based line of the first `env.storage()` access in the fixture. */
const FIRST_STORAGE_LINE = 23;

function readContract(): string {
  return fs.readFileSync(CONTRACT_PATH, "utf-8");
}

function expectWellFormedTtlFinding(finding: Vulnerability): void {
  expect(finding.id).toBe("AP-STORAGE-001");
  expect(finding.severity).toBe("high");
  expect(finding.confidence).toBe("medium");
  expect(finding.location.line).toBeGreaterThan(0);
  expect(finding.message.length).toBeGreaterThan(10);
  expect(finding.message).toContain("extend_ttl");
  expect(finding.remediation).toBeTruthy();
  expect(finding.remediation!.length).toBeGreaterThan(10);
  expect(finding.remediation!).toContain("extend_ttl");
}

describe("contracts/TtlEdgeCases.rs (TTL edge-case fixture)", () => {
  it("exists and exercises temporary vs persistent vs instance storage", () => {
    const code = readContract();
    expect(code).toContain("persistent()");
    expect(code).toContain("temporary()");
    expect(code).toContain("instance()");
  });

  it("reports exactly one file-level AP-STORAGE-001 finding", () => {
    const findings = MissingExtendTtlPlugin.scan(readContract());

    expect(findings).toHaveLength(1);
    expectWellFormedTtlFinding(findings[0]!);
  });

  it("anchors the finding at the first storage access", () => {
    const findings = MissingExtendTtlPlugin.scan(readContract());

    expect(findings[0]?.location.line).toBe(FIRST_STORAGE_LINE);
  });

  it("is picked up by the full engine without errors", () => {
    const engine = new AuditEngine(createDefaultRegistry());
    const findings = engine.run(readContract());
    const ttl = findings.filter((f) => f.id === "AP-STORAGE-001");

    expect(ttl).toHaveLength(1);
    expectWellFormedTtlFinding(ttl[0]!);
  });

  it("a commented-out extend_ttl does not suppress the finding", () => {
    const code = `
      fn save(env: Env, key: Symbol, value: i128) {
        env.storage().persistent().set(&key, &value);
        // env.storage().persistent().extend_ttl(&key, 100, 200);
      }
    `;

    const findings = MissingExtendTtlPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-STORAGE-001");
  });

  it("temporary storage with extend_ttl stays silent", () => {
    const code = `
      fn cache(env: Env, key: Symbol, value: i128) {
        env.storage().temporary().set(&key, &value);
        env.storage().temporary().extend_ttl(&key, 50, 100);
      }
    `;

    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
  });

  it("get_extended counts as a TTL bump", () => {
    const code = `
      fn read(env: Env, key: Symbol) -> i128 {
        env.storage().persistent().get_extended(&key, 100, 200).unwrap_or(0)
      }
    `;

    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
  });
});
