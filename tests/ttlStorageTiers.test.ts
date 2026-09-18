import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { scanTarget } from "../src/scanner";
import { defaultConfig } from "../src/config";
import { toSarifLog } from "../src/reporting/sarif";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

function engine(): AuditEngine {
  return new AuditEngine(createDefaultRegistry());
}

describe("contracts/TtlStorageTiers.rs (Issue #3)", () => {
  const unmanagedPath = path.join(ROOT, "contracts", "TtlStorageTiers.rs");
  const managedPath = path.join(ROOT, "contracts", "TtlStorageTiersManaged.rs");

  it("unmanaged contract triggers AP-STORAGE-001 with precise metadata", () => {
    const code = fs.readFileSync(unmanagedPath, "utf-8");
    const findings = engine().run(code);

    const ttlFindings = findings.filter((f) => f.id === "AP-STORAGE-001");
    expect(ttlFindings).toHaveLength(1);

    const finding = ttlFindings[0]!;
    expect(finding.id).toBe("AP-STORAGE-001");
    expect(finding.severity).toBe("high");
    expect(finding.confidence).toBe("medium");
    expect(finding.location.function).toBe("save_balance");
    expect(finding.location.line).toBeGreaterThan(0);
    expect(finding.message).toContain("extend_ttl");
    expect(finding.remediation).toContain("extend_ttl");

    // All auth checks are present and operations are safe, so unrelated rules stay silent
    expect(findings.filter((f) => f.id === "AP-AUTH-001")).toHaveLength(0);
    expect(findings.filter((f) => f.id === "AP-UPG-001")).toHaveLength(0);
    expect(findings.filter((f) => f.id === "AP-DEBUG-001")).toHaveLength(0);
  });

  it("managed contract with extend_ttl produces zero findings", () => {
    const code = fs.readFileSync(managedPath, "utf-8");
    const findings = engine().run(code);

    expect(findings).toHaveLength(0);
  });

  it("scanner CLI integration correctly flags unmanaged and approves managed", () => {
    const reportUnmanaged = scanTarget(unmanagedPath, engine(), defaultConfig());
    expect(reportUnmanaged.findings).toHaveLength(1);
    expect(reportUnmanaged.findings[0]?.id).toBe("AP-STORAGE-001");
    expect(reportUnmanaged.filesScanned).toBe(1);

    const reportManaged = scanTarget(managedPath, engine(), defaultConfig());
    expect(reportManaged.findings).toHaveLength(0);
    expect(reportManaged.filesScanned).toBe(1);
  });

  it("emits valid SARIF 2.1.0 output for TTL findings", () => {
    const report = scanTarget(unmanagedPath, engine(), defaultConfig());
    const registry = createDefaultRegistry();
    const ruleDescriptions = new Map(registry.all().map((r) => [r.id, r.description]));
    const sarif = toSarifLog(report, { ruleDescriptions }) as any;

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("auditpulse");
    expect(run.results).toHaveLength(1);
    expect(run.results[0].ruleId).toBe("AP-STORAGE-001");
    expect(run.results[0].locations[0].physicalLocation.region.startLine).toBeGreaterThan(0);
  });

  it("recognizes all supported TTL extension syntax variants", () => {
    const codeDirect = `
      fn bump(env: Env) {
        env.storage().persistent().extend_ttl(&key, 100, 200);
      }
    `;
    expect(MissingExtendTtlPlugin.scan(codeDirect)).toHaveLength(0);

    const codeThreshold = `
      fn bump(env: Env) {
        env.storage().persistent().extend_ttl_to_threshold(&key, 100, 200);
      }
    `;
    expect(MissingExtendTtlPlugin.scan(codeThreshold)).toHaveLength(0);

    const codeGetExtended = `
      fn bump(env: Env) {
        env.storage().persistent().get_extended(&key);
      }
    `;
    expect(MissingExtendTtlPlugin.scan(codeGetExtended)).toHaveLength(0);
  });
});
