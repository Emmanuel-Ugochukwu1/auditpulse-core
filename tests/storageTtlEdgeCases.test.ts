import { describe, expect, it, vi } from "vitest";
import fs from "fs";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { defaultConfig } from "../src/config";
import { main, EXIT_FINDINGS } from "../src/cli";
import { createDefaultRegistry } from "../src/registry";
import { extractRustFunctionsAst, parseRust } from "../src/parser/rust";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import { renderSarif } from "../src/reporting/sarif";
import { scanTarget } from "../src/scanner";

const CONTRACT = fileURLToPath(new URL("../contracts/StorageTtlEdgeCases.rs", import.meta.url));
const code = fs.readFileSync(CONTRACT, "utf-8");
const engine = new AuditEngine(createDefaultRegistry());
const ruleDescriptions = new Map(engine.rules().map((rule) => [rule.id, rule.description]));

function fixtureFunction(name: string): string {
  const fn = extractRustFunctionsAst(code)?.find((fn) => fn.name === name);
  expect(fn, `Missing fixture function: ${name}`).toBeDefined();
  return fn!.body;
}

describe("StorageTtlEdgeCases contract", () => {
  it("parses as Rust and reports only the two unchecked reads", () => {
    expect(parseRust(code)?.hasError).toBe(false);
    const report = scanTarget(CONTRACT, engine, defaultConfig());

    expect(report.filesScanned).toBe(1);
    expect(report.findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      function: finding.location.function,
    }))).toEqual([
      { id: "AP-ERROR-001", severity: "high", function: "temporary_unchecked" },
      { id: "AP-ERROR-001", severity: "high", function: "persistent_unchecked" },
    ]);
    // This is the documented file-level heuristic, not proof of TTL safety.
    expect(MissingExtendTtlPlugin.scan(code)).toEqual([]);
  });

  it.each(["temporary_unchecked", "persistent_unchecked"])(
    "reports missing TTL when %s is scanned independently",
    (name) => {
      const findings = MissingExtendTtlPlugin.scan(fixtureFunction(name));
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ id: "AP-STORAGE-001", severity: "high" });
    },
  );

  it.each([
    "temporary_conditional",
    "persistent_early_return",
    "mixed_storage",
    "both_extended",
  ])("recognizes an extension in %s without path or storage-kind analysis", (name) => {
    expect(MissingExtendTtlPlugin.scan(fixtureFunction(name))).toEqual([]);
  });

  it("serializes the real scan with rule metadata, source regions, and remediation", () => {
    const report = scanTarget(CONTRACT, engine, defaultConfig());
    const output = renderSarif(report, { ruleDescriptions });
    const log = JSON.parse(output);

    expect(log.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(log.version).toBe("2.1.0");
    expect(log.runs).toHaveLength(1);
    const run = log.runs[0];
    expect(run.tool.driver.name).toBe("auditpulse");
    expect(run.tool.driver.rules).toEqual([{
      id: "AP-ERROR-001",
      shortDescription: { text: ruleDescriptions.get("AP-ERROR-001") },
      defaultConfiguration: { level: "error" },
    }]);
    expect(run.results).toHaveLength(2);
    report.findings.forEach((finding, index) => {
      expect(code.split("\n")[finding.location.line - 1]).toContain(".get(&key).unwrap()");
      expect(run.results[index]).toEqual({
        ruleId: finding.id,
        level: "error",
        message: { text: finding.message },
        locations: [{ physicalLocation: {
          artifactLocation: { uri: "contracts/StorageTtlEdgeCases.rs" },
          region: { startLine: finding.location.line, startColumn: 9 },
        } }],
        properties: { remediation: finding.remediation },
      });
    });
    expect(output.endsWith("\n")).toBe(true);
    expect(renderSarif(scanTarget(CONTRACT, engine, defaultConfig()), { ruleDescriptions })).toBe(output);
  });

  it.each([
    ["sarif", CONTRACT],
    ["scan", CONTRACT, "--format", "sarif"],
  ])("emits the same SARIF through CLI arguments %j", (...args) => {
    const stdout = vi.spyOn(console, "log").mockImplementation(() => {});
    const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(main(args)).toBe(EXIT_FINDINGS);
      expect(stderr).not.toHaveBeenCalled();
      expect(stdout).toHaveBeenCalledTimes(1);
      expect(JSON.parse(stdout.mock.calls[0]![0])).toEqual(JSON.parse(
        renderSarif(scanTarget(CONTRACT, engine, defaultConfig()), { ruleDescriptions }),
      ));
    } finally {
      stdout.mockRestore();
      stderr.mockRestore();
    }
  });
});

describe("MissingExtendTtlPlugin (AP-STORAGE-001) edge cases", () => {
  it.each(["temporary", "persistent", "instance"])(
    "reports one finding at the first %s access even with multiple reads and writes",
    (kind) => {
      const source = [
        "fn read(env: Env, key: Symbol) {",
        `    let value = env.storage().${kind}().get::<_, u32>(&key);`,
        `    env.storage().${kind}().set(&key, &1u32);`,
        "}",
      ].join("\n");
      const findings = MissingExtendTtlPlugin.scan(source);
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        id: "AP-STORAGE-001",
        severity: "high",
        confidence: "medium",
        location: { line: 2 },
      });
      expect(findings[0]!.message).toContain("extend_ttl");
      expect(findings[0]!.remediation).toContain("extend_ttl");
      expect(engine.run(source).find((f) => f.id === "AP-STORAGE-001")?.location)
        .toEqual({ line: 2, column: 1, function: "read" });
    },
  );

  it.each(["temporary", "persistent"])("recognizes %s extensions and supported helpers", (kind) => {
    for (const extension of [
      "entry.extend_ttl(&key, 100, 200);",
      "entry.extend_ttl_to_threshold(&key, threshold);",
      "entry.get_extended(&key);",
    ]) {
      const source = `fn read(env: Env, key: Symbol) {
        let entry = env.storage().${kind}();
        let value = entry.get::<_, u32>(&key);
        ${extension}
      }`;
      expect(MissingExtendTtlPlugin.scan(source)).toEqual([]);
    }
  });

  it.each(["", "fn no_storage() {}", "// env.storage().temporary().get(&key);",
    "/* env.storage().persistent().set(&key, &1); */"])(
    "ignores input without executable storage access: %s",
    (source) => expect(MissingExtendTtlPlugin.scan(source)).toEqual([]),
  );

  it.each([
    "// env.storage().temporary().extend_ttl(&key, 100, 200);",
    "/* entry.extend_ttl(&key, 100, 200); */",
    "// entry.extend_ttl_to_threshold(&key, threshold);",
    "/* entry.get_extended(&key); */",
  ])("does not count a commented extension: %s", (comment) => {
    const source = `fn read(env: Env, key: Symbol) {
      ${comment}
      env.storage().temporary().get::<_, u32>(&key);
    }`;
    const findings = MissingExtendTtlPlugin.scan(source);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location).toEqual({ line: 3 });
  });

  it("accepts whitespace in storage and TTL calls", () => {
    const source = "fn read(env: Env) { env . storage ( ) . temporary().get::<_, u32>(&key); }";
    expect(MissingExtendTtlPlugin.scan(source)).toHaveLength(1);
    expect(MissingExtendTtlPlugin.scan(`${source}\nfn renew() { entry.extend_ttl ( &key, 100, 200 ); }`))
      .toEqual([]);
  });

  it("reports line-only locations for malformed Rust", () => {
    const source = "fn broken( {\n    env.storage().persistent().get::<_, u32>(&key);\n";
    const findings = engine.run(source).filter((f) => f.id === "AP-STORAGE-001");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location).toEqual({ line: 2 });
  });

  it("serializes a missing-TTL finding as a SARIF error", () => {
    const source = "fn read(env: Env) {\n    env.storage().temporary().get::<_, u32>(&key);\n}";
    const findings = engine.run(source).map((finding) => ({ ...finding, file: "contracts/ttl.rs" }));
    expect(findings.map((f) => f.id)).toEqual(["AP-STORAGE-001"]);
    const log = JSON.parse(renderSarif({ target: "contracts/ttl.rs", filesScanned: 1, findings },
      { ruleDescriptions }));
    expect(log.runs[0].tool.driver.rules).toEqual([{
      id: "AP-STORAGE-001",
      shortDescription: { text: MissingExtendTtlPlugin.description },
      defaultConfiguration: { level: "error" },
    }]);
    expect(log.runs[0].results).toEqual([{
      ruleId: "AP-STORAGE-001",
      level: "error",
      message: { text: findings[0]!.message },
      locations: [{ physicalLocation: {
        artifactLocation: { uri: "contracts/ttl.rs" },
        region: { startLine: 2, startColumn: 1 },
      } }],
      properties: { remediation: findings[0]!.remediation },
    }]);
  });
});
