import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { scanTarget } from "../src/scanner";
import { defaultConfig } from "../src/config";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import { renderSarif } from "../src/reporting/sarif";
import type { Vulnerability } from "../src/types";

/**
 * Fixture coverage for issue #1: temporary vs. persistent storage TTL
 * extensions under edge-case logic.
 *
 * `contracts/TtlStorageTiers.rs` exercises persistent, temporary, and
 * instance storage with no TTL extension plus an expired-read `.unwrap()`.
 * `contracts/TtlStorageTiersManaged.rs` is the clean counterpart where
 * every tier is extended and errors propagate via `Result`.
 */

const CONTRACTS_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
);

function scanContract(fileName: string): Vulnerability[] {
  const code = fs.readFileSync(path.join(CONTRACTS_ROOT, fileName), "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function ofId(findings: Vulnerability[], id: string): Vulnerability[] {
  return findings.filter((f) => f.id === id);
}

describe("TTL storage tiers fixture (issue #1)", () => {
  it("flags the unmanaged tiers with exactly one AP-STORAGE-001", () => {
    const findings = scanContract("TtlStorageTiers.rs");
    const storage = ofId(findings, "AP-STORAGE-001");

    expect(storage).toHaveLength(1);
    const finding = storage[0]!;
    expect(finding.severity).toBe("high");
    expect(finding.confidence).toBe("medium");
    expect(finding.location.line).toBeGreaterThan(0);
    expect(finding.message).toContain("extend_ttl");
    expect(finding.remediation).toContain("extend_ttl");
    // File-level rule points at the first storage access, inside the
    // first writer (`save_balance`).
    expect(finding.location.function).toBe("save_balance");
  });

  it("flags the expired-read edge case with AP-ERROR-001", () => {
    const findings = scanContract("TtlStorageTiers.rs");
    const errors = ofId(findings, "AP-ERROR-001");

    expect(errors).toHaveLength(1);
    expect(errors[0]?.message).toContain(".unwrap()");
    expect(errors[0]?.location.function).toBe("load_balance");
  });

  it("keeps unrelated rules silent on the unmanaged fixture", () => {
    const ids = scanContract("TtlStorageTiers.rs").map((f) => f.id);

    // Writers are require_auth-gated; no token movement, amount math,
    // admin-named functions, or debug macros exist in the fixture.
    expect(ids).not.toContain("AP-AUTH-001");
    expect(ids).not.toContain("AP-CALL-001");
    expect(ids).not.toContain("AP-UPG-001");
    expect(ids).not.toContain("AP-ARITH-001");
    expect(ids).not.toContain("AP-DEBUG-001");
  });

  it("reports zero findings on the managed counterpart", () => {
    expect(scanContract("TtlStorageTiersManaged.rs")).toEqual([]);
  });

  it("treats extend_ttl_to_threshold as a valid extension", () => {
    const code = `
      fn save(env: Env, key: Symbol, value: i128) {
        env.storage().temporary().set(&key, &value);
        env.storage().temporary().extend_ttl_to_threshold(&key, 200);
      }
    `;

    expect(MissingExtendTtlPlugin.scan(code)).toEqual([]);
  });

  it("treats get_extended as a valid extension", () => {
    const code = `
      fn load(env: Env, key: Symbol) {
        let _value: Option<i128> = env.storage().persistent().get_extended(&key, 100, 200);
      }
    `;

    expect(MissingExtendTtlPlugin.scan(code)).toEqual([]);
  });

  it("exposes the TTL finding through SARIF for CI/CD upload", () => {
    const engine = new AuditEngine(createDefaultRegistry());
    const report = scanTarget(
      path.join(CONTRACTS_ROOT, "TtlStorageTiers.rs"),
      engine,
      defaultConfig(),
    );
    const log = JSON.parse(
      renderSarif(report, {
        ruleDescriptions: new Map(
          engine.rules().map((rule) => [rule.id, rule.description]),
        ),
      }),
    ) as any;

    const result = log.runs[0].results.find(
      (r: any) => r.ruleId === "AP-STORAGE-001",
    );
    expect(result).toBeTruthy();
    expect(
      result.locations[0].physicalLocation.region.startLine,
    ).toBeGreaterThan(0);
  });
});
