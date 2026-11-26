import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { renderSarif } from "../src/reporting/sarif";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("TTL fixture through CI output", () => {
  it("surfaces the unmanaged persistent entry in valid SARIF", () => {
    const code = fs.readFileSync(
      path.join(ROOT, "contracts", "TtlStorageCiFixtures.rs"),
      "utf-8",
    );
    const engine = new AuditEngine(createDefaultRegistry());
    const findings = engine
      .run(code)
      .filter((finding) => finding.id === "AP-STORAGE-001");
    const expectedLine =
      code.split("\n").findIndex((line) => line.includes("temporary().set")) + 1;

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("record_session");
    expect(findings[0]?.location.line).toBe(expectedLine);

    const ruleDescriptions = new Map(
      engine.rules().map((rule) => [rule.id, rule.description]),
    );
    const log = JSON.parse(
      renderSarif(
        {
          target: "contracts/TtlStorageCiFixtures.rs",
          filesScanned: 1,
          findings: findings.map((finding) => ({
            ...finding,
            file: "contracts/TtlStorageCiFixtures.rs",
          })),
        },
        { ruleDescriptions },
      ),
    ) as any;

    expect(log.version).toBe("2.1.0");
    expect(log.runs[0].results).toHaveLength(1);
    expect(log.runs[0].results[0].ruleId).toBe("AP-STORAGE-001");
    expect(
      log.runs[0].results[0].locations[0].physicalLocation.region.startLine,
    ).toBe(expectedLine);
    expect(log.runs[0].results[0].properties.precision).toBe("medium");
  });
});
