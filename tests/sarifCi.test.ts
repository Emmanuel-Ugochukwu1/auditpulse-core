import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { scanTarget } from "../src/scanner";
import { resolveConfig } from "../src/config.js";
import { renderSarif } from "../src/reporting/sarif";
import { main, EXIT_OK, EXIT_FINDINGS } from "../src/cli";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("CI/CD SARIF and TTL Storage Tiers (Issue #1)", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
    errSpy.mockRestore();
    vi.restoreAllMocks();
  });

  it("contracts/TtlStorageCi.rs flags unmanaged storage and panicking unwrap", () => {
    const filePath = path.join(ROOT, "contracts", "TtlStorageCi.rs");
    const code = fs.readFileSync(filePath, "utf-8");
    const findings = new AuditEngine(createDefaultRegistry()).run(code);

    const ids = findings.map((f) => f.id).sort();
    expect(ids).toEqual(["AP-ERROR-001", "AP-STORAGE-001"]);

    const storageFinding = findings.find((f) => f.id === "AP-STORAGE-001");
    expect(storageFinding?.severity).toBe("high");
    expect(storageFinding?.location.function).toBe("save_persistent");

    const errorFinding = findings.find((f) => f.id === "AP-ERROR-001");
    expect(errorFinding?.severity).toBe("high");
    expect(errorFinding?.location.function).toBe("load_persistent");
  });

  it("contracts/TtlStorageCiManaged.rs produces 0 findings across all rules", () => {
    const filePath = path.join(ROOT, "contracts", "TtlStorageCiManaged.rs");
    const code = fs.readFileSync(filePath, "utf-8");
    const findings = new AuditEngine(createDefaultRegistry()).run(code);

    expect(findings).toEqual([]);
  });

  it("temporary vs. persistent TTL suppression edge cases", () => {
    const engine = new AuditEngine(createDefaultRegistry());

    // Persistent storage write with valid extend_ttl
    const persistentExtended = [
      "pub fn store(env: Env, u: Address, a: i128) {",
      "  u.require_auth();",
      "  env.storage().persistent().set(&u, &a);",
      "  env.storage().persistent().extend_ttl(&u, 100, 200);",
      "}",
    ].join("\n");
    expect(engine.run(persistentExtended).filter((f) => f.id === "AP-STORAGE-001")).toHaveLength(0);

    // Temporary storage write with extend_ttl_to_threshold
    const temporaryThreshold = [
      "pub fn temp(env: Env, u: Address, s: Symbol, a: i128) {",
      "  u.require_auth();",
      "  env.storage().temporary().set(&s, &a);",
      "  env.storage().temporary().extend_ttl_to_threshold(&s, 50, 150);",
      "}",
    ].join("\n");
    expect(engine.run(temporaryThreshold).filter((f) => f.id === "AP-STORAGE-001")).toHaveLength(0);

    // Commented out extend_ttl does not suppress
    const commentedOut = [
      "pub fn temp(env: Env, u: Address, s: Symbol, a: i128) {",
      "  u.require_auth();",
      "  env.storage().temporary().set(&s, &a);",
      "  // env.storage().temporary().extend_ttl(&s, 50, 150);",
      "}",
    ].join("\n");
    expect(engine.run(commentedOut).filter((f) => f.id === "AP-STORAGE-001")).toHaveLength(1);
  });

  it("generates valid SARIF 2.1.0 for contracts/TtlStorageCi.rs", () => {
    const relFile = "contracts/TtlStorageCi.rs";
    const absFile = path.join(ROOT, relFile);
    const registry = createDefaultRegistry();
    const engine = new AuditEngine(registry);
    const config = resolveConfig({}, registry.all().map((r) => r.id));
    const report = scanTarget(absFile, engine, config);

    const ruleDescriptions = new Map(registry.all().map((r) => [r.id, r.description]));
    const sarifJson = renderSarif(report, { ruleDescriptions });
    const parsed = JSON.parse(sarifJson);

    expect(parsed.version).toBe("2.1.0");
    expect(parsed.$schema).toContain("sarif-2.1.0");
    expect(parsed.runs).toHaveLength(1);

    const run = parsed.runs[0];
    expect(run.tool.driver.name).toBe("auditpulse");
    expect(run.results).toHaveLength(2);

    const ruleIds = run.results.map((r: any) => r.ruleId).sort();
    expect(ruleIds).toEqual(["AP-ERROR-001", "AP-STORAGE-001"]);

    for (const res of run.results) {
      expect(res.level).toBe("error");
      expect(res.locations[0].physicalLocation.artifactLocation.uri).toBe("contracts/TtlStorageCi.rs");
      expect(res.locations[0].physicalLocation.region.startLine).toBeGreaterThan(0);
      expect(res.locations[0].physicalLocation.region.startColumn).toBeGreaterThan(0);
    }
  });

  it("CLI scan produces SARIF format with appropriate exit codes for CI/CD", () => {
    const unmanagedPath = path.join(ROOT, "contracts", "TtlStorageCi.rs");
    const managedPath = path.join(ROOT, "contracts", "TtlStorageCiManaged.rs");

    // Scanning unmanaged contract in SARIF format returns EXIT_FINDINGS (1)
    const exitUnmanaged = main(["scan", unmanagedPath, "--format", "sarif"]);
    expect(exitUnmanaged).toBe(EXIT_FINDINGS);

    const unmanagedLog = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    const unmanagedSarif = JSON.parse(unmanagedLog);
    expect(unmanagedSarif.runs[0].results.length).toBeGreaterThan(0);

    logSpy.mockClear();

    // Scanning managed contract in SARIF format returns EXIT_OK (0)
    const exitManaged = main(["sarif", managedPath]);
    expect(exitManaged).toBe(EXIT_OK);

    const managedLog = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    const managedSarif = JSON.parse(managedLog);
    expect(managedSarif.runs[0].results).toHaveLength(0);
  });
});
