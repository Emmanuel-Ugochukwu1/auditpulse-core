import { renderJson } from "../src/reporting/json";
import { renderSarif } from "../src/reporting/sarif";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { scanTarget, InputError, sortFindings } from "../src/scanner";
import type { FileFinding } from "../src/scanner";
import { defaultConfig } from "../src/config";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "auditpulse-scan-"));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(relPath: string, contents: string): void {
  const abs = path.join(tmp, relPath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, contents);
}

const VULNERABLE = `
  fn withdraw(env: Env, to: Address, amount: i128) {
    let client = token::Client::new(&env, &token_id);
    client.transfer(&to, &amount);
  }
`;

const CLEAN = `
  fn add(a: i128, b: i128) -> i128 {
    a + b
  }
`;

function engine(): AuditEngine {
  return new AuditEngine(createDefaultRegistry());
}

describe("scanTarget: single file", () => {
  it("scans one file and reports a cwd-relative path when under the working directory", () => {
    write("vault.rs", VULNERABLE);
    const cwdBackup = process.cwd();
    process.chdir(tmp);
    try {
      const report = scanTarget("vault.rs", engine(), defaultConfig());

      expect(report.filesScanned).toBe(1);
      expect(report.findings.length).toBeGreaterThan(0);
      for (const finding of report.findings) {
        expect(finding.file).toBe("vault.rs");
      }
    } finally {
      process.chdir(cwdBackup);
    }
  });

  it("reports an absolute forward-slash path for files outside the working directory", () => {
    write("vault.rs", VULNERABLE);

    const report = scanTarget(path.join(tmp, "vault.rs"), engine(), defaultConfig());

    expect(report.findings.length).toBeGreaterThan(0);
    for (const finding of report.findings) {
      expect(finding.file).toBe(path.join(tmp, "vault.rs").split(path.sep).join("/"));
    }
  });

  it("returns zero findings for a clean file", () => {
    write("clean.rs", CLEAN);

    const report = scanTarget(path.join(tmp, "clean.rs"), engine(), defaultConfig());

    expect(report.filesScanned).toBe(1);
    expect(report.findings).toEqual([]);
  });

  it("rejects non-Rust files with InputError", () => {
    write("notes.txt", "hello");

    expect(() => scanTarget(path.join(tmp, "notes.txt"), engine(), defaultConfig())).toThrow(
      InputError,
    );
  });

  it("rejects missing paths with InputError", () => {
    expect(() => scanTarget(path.join(tmp, "ghost.rs"), engine(), defaultConfig())).toThrow(
      InputError,
    );
  });
});

describe("scanTarget: directory", () => {
  it("prefixes findings with the scanned directory path", () => {
    write("src/a.rs", VULNERABLE);
    const cwdBackup = process.cwd();
    process.chdir(tmp);
    try {
      const report = scanTarget("src", engine(), defaultConfig());

      expect(report.filesScanned).toBe(1);
      for (const finding of report.findings) {
        expect(finding.file).toBe("src/a.rs");
      }
    } finally {
      process.chdir(cwdBackup);
    }
  });

  it("scans every Rust file in the tree, once each", () => {
    write("src/a.rs", VULNERABLE);
    write("src/b.rs", CLEAN);
    write("src/deep/c.rs", VULNERABLE);
    write("src/notes.txt", "ignored");

    const report = scanTarget(tmp, engine(), defaultConfig());

    expect(report.filesScanned).toBe(3);
    const files = [...new Set(report.findings.map((f) => f.file))];
    expect(files).toHaveLength(2);
  });

  it("scans multiple files independently and reports each file's findings", () => {
    write("one.rs", VULNERABLE);
    write("two.rs", VULNERABLE);
    write("three.rs", CLEAN);

    const report = scanTarget(tmp, engine(), defaultConfig());

    const perFile = new Map<string, number>();
    for (const finding of report.findings) {
      perFile.set(finding.file, (perFile.get(finding.file) ?? 0) + 1);
    }
    expect(perFile.size).toBe(2);
    for (const count of perFile.values()) {
      expect(count).toBeGreaterThan(0);
    }
  });

  it("applies disabled rules from configuration", () => {
    write("one.rs", VULNERABLE);

    const config = { ...defaultConfig(), disabledRules: ["AP-AUTH-001"] };
    const report = scanTarget(tmp, engine(), config);

    expect(report.findings.map((f) => f.id)).not.toContain("AP-AUTH-001");
  });

  it("applies the minimum severity threshold", () => {
    write("one.rs", VULNERABLE);

    const all = scanTarget(tmp, engine(), defaultConfig());
    const criticalOnly = scanTarget(tmp, engine(), {
      ...defaultConfig(),
      minSeverity: "critical",
    });

    expect(all.findings.length).toBeGreaterThan(0);
    for (const finding of criticalOnly.findings) {
      expect(finding.severity).toBe("critical");
    }
    expect(criticalOnly.findings.length).toBeLessThanOrEqual(all.findings.length);
  });
});

describe("location regression through scanTarget", () => {
  it("attaches file, line, column and function to findings on well-formed source", () => {
    write("vault.rs", VULNERABLE);
    const cwdBackup = process.cwd();
    process.chdir(tmp);
    try {
      const report = scanTarget("vault.rs", engine(), defaultConfig());

      const auth = report.findings.find((f) => f.id === "AP-AUTH-001");
      expect(auth).toBeDefined();
      expect(auth?.file).toBe("vault.rs");
      expect(auth?.location.line).toBeGreaterThan(0);
      expect(auth?.location.function).toBe("withdraw");
      // Tree-sitter is available in this repo, so the AST-precise column
      // must reach the file-scan layer.
      expect(auth?.location.column).toBeGreaterThan(0);
    } finally {
      process.chdir(cwdBackup);
    }
  });

  it("keeps every finding well-formed across a directory scan", () => {
    write("src/a.rs", VULNERABLE);
    write("src/b.rs", VULNERABLE);

    const report = scanTarget(tmp, engine(), defaultConfig());

    expect(report.filesScanned).toBe(2);
    for (const finding of report.findings) {
      expect(finding.file.length).toBeGreaterThan(0);
      expect(finding.location.line).toBeGreaterThan(0);
      if (finding.location.column !== undefined) {
        expect(finding.location.column).toBeGreaterThan(0);
      }
    }
  });
});

describe("sortFindings", () => {
  it("orders by file, then line, then rule id", () => {
    const base = { message: "m", severity: "high" as const };
    const findings: FileFinding[] = [
      { ...base, id: "AP-Z-001", file: "a.rs", location: { line: 2 } },
      { ...base, id: "AP-A-001", file: "a.rs", location: { line: 10 } },
      { ...base, id: "AP-A-001", file: "a.rs", location: { line: 2 } },
      { ...base, id: "AP-A-001", file: "b.rs", location: { line: 1 } },
    ];

    const sorted = sortFindings(findings);

    expect(sorted.map((f) => `${f.file}:${f.location.line}:${f.id}`)).toEqual([
      "a.rs:2:AP-A-001",
      "a.rs:2:AP-Z-001",
      "a.rs:10:AP-A-001",
      "b.rs:1:AP-A-001",
    ]);
  });
});

describe("severity_overrides and inline suppressions integration (#17)", () => {
  it("applies severity_overrides before min_severity filtering and preserves valid JSON/SARIF output", () => {
    write(
      "vault.rs",
      [
        "fn save(env: Env, k: Symbol, v: i128) {",
        "  env.storage().persistent().set(&k, &v);",
        "}",
      ].join("\n"),
    );

    const downgradedConfig = {
      ...defaultConfig(),
      minSeverity: "medium" as const,
      severityOverrides: {
        "AP-STORAGE-001": "medium" as const,
        "AP-AUTH-001": "low" as const,
      },
    };

    const report = scanTarget(tmp, engine(), downgradedConfig);
    // AP-AUTH-001 was downgraded to "low" (below minSeverity "medium"), so it is filtered out.
    // AP-STORAGE-001 was downgraded from "high" to "medium", surviving with severity "medium".
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.id).toBe("AP-STORAGE-001");
    expect(report.findings[0]?.severity).toBe("medium");

    const json = JSON.parse(renderJson(report));
    expect(json.summary.findingCount).toBe(1);
    expect(json.summary.bySeverity).toEqual({ medium: 1 });
    expect(json.findings[0]?.severity).toBe("medium");

    const sarif = JSON.parse(
      renderSarif(report, {
        ruleDescriptions: new Map(
          createDefaultRegistry().all().map((r) => [r.id, r.description]),
        ),
      }),
    );
    expect(sarif.runs[0]?.results).toHaveLength(1);
    expect(sarif.runs[0]?.results[0]?.ruleId).toBe("AP-STORAGE-001");
    expect(sarif.runs[0]?.results[0]?.level).toBe("warning");
  });

  it("suppresses findings with auditpulse-ignore <RULE-ID> on the same line or line above, ignoring 'all'", () => {
    write(
      "suppressed.rs",
      [
        "fn demo(env: Env, user: Address) -> i128 {",
        "  // auditpulse-ignore AP-ERROR-001",
        "  let a: i128 = env.storage().persistent().get(&user).unwrap();",
        "  let b: i128 = env.storage().persistent().get(&user).unwrap(); // auditpulse-ignore AP-ERROR-001",
        "  // auditpulse-ignore all",
        "  let c: i128 = env.storage().persistent().get(&user).unwrap();",
        "  env.storage().persistent().extend_ttl(&user, 100, 200);",
        "  a",
        "}",
      ].join("\n"),
    );

    const report = scanTarget(tmp, engine(), defaultConfig());
    const errorFindings = report.findings.filter((f) => f.id === "AP-ERROR-001");
    // Lines 3 and 4 are suppressed; line 6 ('auditpulse-ignore all') is NOT suppressed.
    expect(errorFindings).toHaveLength(1);
    expect(errorFindings[0]?.location.line).toBe(6);
  });
});
