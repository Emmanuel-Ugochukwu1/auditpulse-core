import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import { scanTarget } from "../src/scanner";
import { resolveConfig } from "../src/config.js";
import { renderSarif } from "../src/reporting/sarif";
import { main, EXIT_OK, EXIT_FINDINGS } from "../src/cli";
import type { Vulnerability } from "../src/types";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONTRACTS_DIR = path.join(ROOT, "contracts");

function runEngine(code: string): Vulnerability[] {
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function ttlFindings(code: string): Vulnerability[] {
  return runEngine(code).filter((f) => f.id === "AP-STORAGE-001");
}

describe("TTL and storage expiration edge-case fixtures (Issues #1 & #3)", () => {
  const managedContractPath = path.join(CONTRACTS_DIR, "TtlStorageEdgeCases.rs");
  const unmanagedContractPath = path.join(CONTRACTS_DIR, "TtlStorageUnmanaged.rs");

  it("scans contracts/TtlStorageEdgeCases.rs cleanly across persistent, temporary, and instance tiers", () => {
    expect(fs.existsSync(managedContractPath)).toBe(true);
    const code = fs.readFileSync(managedContractPath, "utf-8");

    expect(code).toMatch(/env\.storage\(\)\.persistent\(\)/);
    expect(code).toMatch(/env\.storage\(\)\.temporary\(\)/);
    expect(code).toMatch(/env\.storage\(\)\.instance\(\)/);
    expect(code).toMatch(/\.extend_ttl\(/);
    expect(code).toMatch(/\.extend_ttl_to_threshold\(/);
    expect(code).toMatch(/\.get_extended\(/);

    const findings = runEngine(code);
    expect(findings).toEqual([]);
  });

  it("flags unextended storage and panicking unwrap in contracts/TtlStorageUnmanaged.rs", () => {
    expect(fs.existsSync(unmanagedContractPath)).toBe(true);
    const code = fs.readFileSync(unmanagedContractPath, "utf-8");
    const findings = runEngine(code);

    const ids = findings.map((f) => f.id).sort();
    expect(ids).toEqual(["AP-ERROR-001", "AP-STORAGE-001"]);

    const storageFinding = findings.find((f) => f.id === "AP-STORAGE-001");
    expect(storageFinding?.severity).toBe("high");
    expect(storageFinding?.confidence).toBe("medium");
    expect(storageFinding?.location.function).toBe("store_persistent_unextended");

    const errorFinding = findings.find((f) => f.id === "AP-ERROR-001");
    expect(errorFinding?.severity).toBe("high");
    expect(errorFinding?.location.function).toBe("read_expired_with_unwrap");
  });

  it("distinguishes valid TTL extensions across temporary, persistent, and instance storage", () => {
    const persistentWithExtend = `
      fn save_balance(env: Env, user: Address, amount: i128) {
        let storage = env.storage().persistent();
        storage.set(&user, &amount);
        storage.extend_ttl(&user, 100, 200);
      }
    `;
    expect(ttlFindings(persistentWithExtend)).toHaveLength(0);

    const temporaryWithThreshold = `
      fn cache_quote(env: Env, id: u32) {
        let storage = env.storage().temporary();
        storage.set(&id, &1u32);
        storage.extend_ttl_to_threshold(&id, 50);
      }
    `;
    expect(ttlFindings(temporaryWithThreshold)).toHaveLength(0);

    const persistentGetExtended = `
      fn read_balance(env: Env, user: Address) -> Option<i128> {
        env.storage().persistent().get_extended(&user)
      }
    `;
    expect(ttlFindings(persistentGetExtended)).toHaveLength(0);

    const instanceExtend = `
      fn bump_instance(env: Env) {
        env.storage().instance().extend_ttl(100, 1000);
      }
    `;
    expect(ttlFindings(instanceExtend)).toHaveLength(0);
  });

  it("reports AP-STORAGE-001 when extend_ttl is commented out or absent", () => {
    const commentedExtension = `
      fn read_temp(env: Env, key: Symbol) -> Option<i128> {
        // env.storage().temporary().extend_ttl(&key, 50, 100);
        env.storage().temporary().get(&key)
      }
    `;
    const findings = ttlFindings(commentedExtension);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("read_temp");

    const standalone = MissingExtendTtlPlugin.scan(
      "fn broken( {\n  env.storage().temporary().get(&k);\n",
    );
    expect(standalone).toHaveLength(1);
    expect(standalone[0]?.location.line).toBe(2);
    expect(standalone[0]?.location.column).toBeUndefined();
  });
});

describe("SARIF 2.1.0 CI/CD output on TTL storage fixtures (Issue #1)", () => {
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

  it("renders valid SARIF 2.1.0 with normalized forward-slash URIs for contracts/TtlStorageUnmanaged.rs", () => {
    const absFile = path.join(CONTRACTS_DIR, "TtlStorageUnmanaged.rs");
    const registry = createDefaultRegistry();
    const engine = new AuditEngine(registry);
    const config = resolveConfig({}, registry.all().map((r) => r.id));
    const report = scanTarget(absFile, engine, config);

    const ruleDescriptions = new Map(
      registry.all().map((r) => [r.id, r.description]),
    );
    const sarif = JSON.parse(renderSarif(report, { ruleDescriptions }));

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-2.1.0");
    expect(sarif.runs).toHaveLength(1);

    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("auditpulse");
    expect(run.results).toHaveLength(2);
    expect(run.results.map((r: any) => r.ruleId).sort()).toEqual([
      "AP-ERROR-001",
      "AP-STORAGE-001",
    ]);

    for (const res of run.results) {
      expect(res.level).toBe("error");
      expect(res.locations[0].physicalLocation.artifactLocation.uri).toBe(
        "contracts/TtlStorageUnmanaged.rs",
      );
      expect(
        res.locations[0].physicalLocation.region.startLine,
      ).toBeGreaterThan(0);
    }
  });

  it("CLI SARIF mode returns EXIT_OK (0) on TtlStorageEdgeCases.rs and EXIT_FINDINGS (1) on TtlStorageUnmanaged.rs", () => {
    const managedPath = path.join(CONTRACTS_DIR, "TtlStorageEdgeCases.rs");
    const unmanagedPath = path.join(CONTRACTS_DIR, "TtlStorageUnmanaged.rs");

    expect(main(["scan", managedPath, "--format", "sarif"])).toBe(EXIT_OK);
    const cleanSarif = JSON.parse(
      logSpy.mock.calls.map((c) => c.join(" ")).join("\n"),
    );
    expect(cleanSarif.runs[0].results).toHaveLength(0);

    logSpy.mockClear();

    expect(main(["scan", unmanagedPath, "--format", "sarif"])).toBe(
      EXIT_FINDINGS,
    );
    const findingSarif = JSON.parse(
      logSpy.mock.calls.map((c) => c.join(" ")).join("\n"),
    );
    expect(findingSarif.runs[0].results).toHaveLength(2);
  });
});
