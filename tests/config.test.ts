import { describe, it, expect } from "vitest";
import {
  ConfigError,
  SEVERITY_ORDER,
  defaultConfig,
  findConfigFile,
  parseConfig,
  resolveConfig,
} from "../src/config";
import type { Severity } from "../src/types";

const RULE_IDS = [
  "AP-AUTH-001",
  "AP-ERROR-001",
  "AP-STORAGE-001",
  "AP-ARITH-001",
  "AP-CALL-001",
  "AP-UPG-001",
  "AP-DEBUG-001",
  "AP-BOUND-001",
];

describe("parseConfig", () => {
  it("parses all supported keys", () => {
    const parsed = parseConfig(
      [
        "# comment",
        'disabled_rules = ["AP-DEBUG-001", "AP-ERROR-001"]',
        'min_severity = "medium"',
        'exclude = ["vendor", "src/gen"]',
      ].join("\n"),
    );

    expect(parsed).toEqual({
      disabledRules: ["AP-DEBUG-001", "AP-ERROR-001"],
      minSeverity: "medium",
      exclude: ["vendor", "src/gen"],
    });
  });

  it("ignores comments and unknown keys", () => {
    const parsed = parseConfig(
      [
        "# a comment",
        "min_severity = \"high\" # trailing comment",
        "project_name = \"vault\"",
        "",
      ].join("\n"),
    );

    expect(parsed).toEqual({ minSeverity: "high" });
  });

  it("accepts single quotes and empty arrays", () => {
    const parsed = parseConfig(
      ["min_severity = 'low'", "exclude = []"].join("\n"),
    );

    expect(parsed).toEqual({ minSeverity: "low", exclude: [] });
  });

  it("returns an empty object for an empty file", () => {
    expect(parseConfig("")).toEqual({});
  });

  it("rejects malformed lines", () => {
    expect(() => parseConfig("disabled_rules [\"AP\"]")).toThrow(ConfigError);
    expect(() => parseConfig("= \"value\"")).toThrow(ConfigError);
    expect(() => parseConfig("min_severity = huge")).toThrow(ConfigError);
    expect(() => parseConfig('exclude = ["a",]')).toThrow(ConfigError);
  });

  it("rejects unknown min_severity values", () => {
    expect(() => parseConfig('min_severity = "extreme"')).toThrow(ConfigError);
  });
});

describe("resolveConfig", () => {
  it("fills defaults when nothing is set", () => {
    const config = resolveConfig({}, RULE_IDS);

    expect(config).toEqual({
      disabledRules: [],
      minSeverity: "low",
      exclude: [],
    });
    expect(config).toEqual(defaultConfig());
  });

  it("merges parsed values over defaults", () => {
    const config = resolveConfig({ exclude: ["gen"] }, RULE_IDS);

    expect(config.disabledRules).toEqual([]);
    expect(config.minSeverity).toBe("low");
    expect(config.exclude).toEqual(["gen"]);
  });

  it("rejects unknown rule ids", () => {
    expect(() => resolveConfig({ disabledRules: ["AP-NOPE-001"] }, RULE_IDS)).toThrow(
      /Unknown rule id/,
    );
  });
});

describe("findConfigFile", () => {
  const readFile = (p: string): string | null =>
    ({
      "C:/proj/auditpulse.toml": "min_severity = \"high\"",
      "C:/auditpulse.toml": "min_severity = \"low\"",
    })[p.replace(/\\/g, "/")] ?? null;

  it("finds the nearest config walking up", () => {
    expect(findConfigFile("C:/proj/src/sub", readFile)).toBe(
      "C:/proj/auditpulse.toml",
    );
  });

  it("returns null when no config exists", () => {
    expect(findConfigFile("C:/nowhere", () => null)).toBeNull();
  });
});

describe("SEVERITY_ORDER", () => {
  it("ranks severities monotonically", () => {
    const levels: Severity[] = ["low", "medium", "high", "critical"];
    for (let i = 1; i < levels.length; i++) {
      expect(SEVERITY_ORDER[levels[i]!]).toBeGreaterThan(
        SEVERITY_ORDER[levels[i - 1]!],
      );
    }
  });
});
