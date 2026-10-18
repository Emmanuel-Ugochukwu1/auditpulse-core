import type { Severity, Vulnerability } from "./types";

/**
 * Lightweight AuditPulse configuration.
 *
 * Loads `auditpulse.toml` when present (no dependencies: only the flat
 * `key = "value"` subset described below is understood) and falls back to
 * sensible defaults when no file exists.
 *
 * Supported keys:
 *   disabled_rules     = ["AP-DEBUG-001", ...]
 *   min_severity       = "low" | "medium" | "high" | "critical"
 *   exclude            = ["node_modules", ...]  (path fragments, forward slashes)
 *   severity_overrides = { "AP-STORAGE-001" = "medium", ... }
 *
 * Unknown keys are ignored. Invalid values are reported as errors rather
 * than guessed at.
 */
export interface AuditPulseConfig {
  /** Rule ids that must not run. */
  disabledRules: string[];
  /** Findings below this severity are dropped. Default: "low" (report all). */
  minSeverity: Severity;
  /** Path fragments (forward-slash separated) to skip during discovery. */
  exclude: string[];
  /** Per-rule severity overrides applied before threshold filtering. */
  severityOverrides: Record<string, Severity>;
}

/** Severity ranking used for both filtering and sorting. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

export const MIN_SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

/** Configuration used when no file exists or nothing is overridden. */
export function defaultConfig(): AuditPulseConfig {
  return {
    disabledRules: [],
    minSeverity: "low",
    exclude: [],
    severityOverrides: {},
  };
}

/** Error thrown when the configuration file is malformed. */
export class ConfigError extends Error {}

/**
 * Locates `auditpulse.toml` for `startPath`: the start path itself (when it
 * is a directory), then walking up its parent directories. Returns null when
 * nothing is found.
 */
export function findConfigFile(
  startPath: string,
  readFile: (path: string) => string | null,
): string | null {
  let dir = startPath;
  for (;;) {
    if (dir === "") return null;
    const candidate = joinPath(dir, "auditpulse.toml");
    const contents = readFile(candidate);
    if (contents !== null) return candidate;

    const parent = parentDir(dir);
    if (parent === dir || parent === "") return null;
    dir = parent;
  }
}

/**
 * Parses auditpulse.toml contents. Throws ConfigError on structural
 * problems; the returned config contains only the keys actually present.
 */
export function parseConfig(text: string): Partial<AuditPulseConfig> {
  const result: Partial<AuditPulseConfig> = {};
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = stripComment(lines[i] ?? "").trim();
    if (line === "") continue;

    const eq = line.indexOf("=");
    const key = eq <= 0 ? "" : line.slice(0, eq).trim();
    if (key === "" || /\s/.test(key)) {
      throw new ConfigError(
        `auditpulse.toml line ${i + 1}: expected "key = value", got: ${line}`,
      );
    }
    const rawValue = line.slice(eq + 1).trim();
    switch (key) {
      case "disabled_rules":
        result.disabledRules = parseStringArray(rawValue, i + 1);
        break;
      case "exclude":
        result.exclude = parseStringArray(rawValue, i + 1);
        break;
      case "min_severity":
        result.minSeverity = parseSeverity(rawValue, i + 1);
        break;
      case "severity_overrides":
        result.severityOverrides = parseSeverityOverrides(rawValue, i + 1);
        break;
      default:
        // Unknown keys are ignored so the file can carry project metadata.
        break;
    }
  }

  return result;
}

/**
 * Merges parsed file values over the defaults, validating rule ids and
 * severity levels along the way.
 */
export function resolveConfig(
  parsed: Partial<AuditPulseConfig>,
  knownRuleIds: string[],
): AuditPulseConfig {
  const config = defaultConfig();

  for (const ruleId of parsed.disabledRules ?? []) {
    if (!knownRuleIds.includes(ruleId)) {
      throw new ConfigError(`Unknown rule id in configuration: ${ruleId}`);
    }
    config.disabledRules.push(ruleId);
  }

  if (parsed.minSeverity !== undefined) {
    config.minSeverity = parsed.minSeverity;
  }

  config.exclude.push(...(parsed.exclude ?? []));

  for (const [ruleId, severity] of Object.entries(parsed.severityOverrides ?? {})) {
    if (!knownRuleIds.includes(ruleId)) {
      throw new ConfigError(`Unknown rule id in severity_overrides: ${ruleId}`);
    }
    if (!MIN_SEVERITIES.includes(severity)) {
      throw new ConfigError(
        `Invalid severity in severity_overrides for ${ruleId}: ${severity}`,
      );
    }
    config.severityOverrides[ruleId] = severity;
  }

  return config;
}

/**
 * Extracts per-line inline suppression directives (`auditpulse-ignore <RULE-ID>`)
 * from Rust line or block comments. Only exact rule IDs (`AP-XXX-NNN`) are
 * recorded; shorthand tokens like `all` are ignored.
 */
export function parseInlineSuppressions(code: string): Map<number, Set<string>> {
  const map = new Map<number, Set<string>>();
  const lines = code.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const commentText = extractCommentText(lines[i] ?? "");
    if (!commentText.includes("auditpulse-ignore")) continue;

    const directive = /auditpulse-ignore\s+([^*/\r\n]+)/g;
    let m: RegExpExecArray | null;
    while ((m = directive.exec(commentText)) !== null) {
      const tail = m[1] ?? "";
      // Match exact rule tokens; stop before trailing explanation after "--" or ";"
      const tokens = tail
        .split(/[\s,]+/)
        .map((t) => t.trim())
        .filter((t) => t.length > 0);
      for (const token of tokens) {
        if (/^AP-[A-Z]+-\d{3}$/.test(token)) {
          const lineNo = i + 1;
          let set = map.get(lineNo);
          if (!set) {
            set = new Set<string>();
            map.set(lineNo, set);
          }
          set.add(token);
        } else {
          // Stop parsing rule tokens once non-rule prose or an invalid shorthand is hit
          break;
        }
      }
    }
  }

  return map;
}

/**
 * Filters out findings suppressed by an `auditpulse-ignore <RULE-ID>` comment
 * on the finding's own line or the line immediately above it.
 */
export function applyInlineSuppressions<T extends Vulnerability>(
  code: string,
  findings: readonly T[],
): T[] {
  const suppressions = parseInlineSuppressions(code);
  if (suppressions.size === 0) {
    return [...findings];
  }
  return findings.filter((finding) => {
    const line = finding.location.line;
    if (suppressions.get(line)?.has(finding.id)) return false;
    if (suppressions.get(line - 1)?.has(finding.id)) return false;
    return true;
  });
}

function extractCommentText(line: string): string {
  let inString = false;
  let escaped = false;
  for (let i = 0; i < line.length - 1; i++) {
    const ch = line[i]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (inString) {
      if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === "/" && (line[i + 1] === "/" || line[i + 1] === "*")) {
      return line.slice(i + 2);
    }
  }
  return "";
}

function parseSeverityOverrides(
  raw: string,
  lineNo: number,
): Record<string, Severity> {
  if (!raw.startsWith("{") || !raw.endsWith("}")) {
    throw new ConfigError(
      `auditpulse.toml line ${lineNo}: expected an inline table like { "AP-STORAGE-001" = "medium" }, got: ${raw}`,
    );
  }

  const inner = raw.slice(1, -1).trim();
  if (inner === "") return {};

  const overrides: Record<string, Severity> = {};
  for (const part of inner.split(",")) {
    const entry = part.trim();
    const eq = entry.indexOf("=");
    if (eq <= 0) {
      throw new ConfigError(
        `auditpulse.toml line ${lineNo}: expected "RULE_ID = \"severity\"" in severity_overrides, got: ${entry}`,
      );
    }
    const rawKey = entry.slice(0, eq).trim();
    const rawVal = entry.slice(eq + 1).trim();
    const ruleId = stripQuotes(rawKey).trim();
    if (!ruleId || /\s/.test(ruleId)) {
      throw new ConfigError(
        `auditpulse.toml line ${lineNo}: invalid rule id in severity_overrides: ${rawKey}`,
      );
    }
    const valMatch = /^"([^"]*)"$/.exec(rawVal) ?? /^'([^']*)'$/.exec(rawVal);
    if (!valMatch) {
      throw new ConfigError(
        `auditpulse.toml line ${lineNo}: severity override value must be a quoted string, got: ${rawVal}`,
      );
    }
    const severity = valMatch[1] ?? "";
    if (!MIN_SEVERITIES.includes(severity as Severity)) {
      throw new ConfigError(
        `auditpulse.toml line ${lineNo}: severity override for ${ruleId} must be one of ${MIN_SEVERITIES.join(", ")}, got: ${rawVal}`,
      );
    }
    overrides[ruleId] = severity as Severity;
  }

  return overrides;
}

function parseStringArray(raw: string, lineNo: number): string[] {
  if (!raw.startsWith("[") || !raw.endsWith("]")) {
    throw new ConfigError(
      `auditpulse.toml line ${lineNo}: expected an array like ["a", "b"], got: ${raw}`,
    );
  }

  const inner = raw.slice(1, -1).trim();
  if (inner === "") return [];

  const items: string[] = [];
  // Simple split: TOML string arrays in a config file are comma separated.
  for (const item of inner.split(",")) {
    const value = item.trim();
    const match = /^"([^"]*)"$/.exec(value) ?? /^'([^']*)'$/.exec(value);
    if (!match) {
      throw new ConfigError(
        `auditpulse.toml line ${lineNo}: array items must be quoted strings, got: ${value}`,
      );
    }
    items.push(match[1] ?? "");
  }

  return items;
}

function parseSeverity(raw: string, lineNo: number): Severity {
  const value = stripQuotes(raw);
  if (!MIN_SEVERITIES.includes(value as Severity)) {
    throw new ConfigError(
      `auditpulse.toml line ${lineNo}: min_severity must be one of ${MIN_SEVERITIES.join(", ")}, got: ${raw}`,
    );
  }
  return value as Severity;
}

function stripComment(line: string): string {
  let inDouble = false;
  let inSingle = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === "#" && !inDouble && !inSingle) {
      return line.slice(0, i);
    }
  }
  return line;
}

function stripQuotes(raw: string): string {
  const match = /^"([^"]*)"$/.exec(raw) ?? /^'([^']*)'$/.exec(raw);
  return match ? (match[1] ?? "") : raw;
}

function joinPath(dir: string, file: string): string {
  return dir.endsWith("/") || dir.endsWith("\\")
    ? `${dir}${file}`
    : `${dir}/${file}`;
}

function parentDir(dir: string): string {
  // Strip trailing slashes but keep a lone root "/" intact.
  const normalized = dir === "/" ? dir : dir.replace(/[\\/]+$/, "");
  const cut = Math.max(
    normalized.lastIndexOf("/"),
    normalized.lastIndexOf("\\"),
  );
  if (cut < 0) return ""; // bare name like "fixtures" or "C:" -> no parent
  if (cut === 0) return "/"; // parent of "/home" is "/"
  return normalized.slice(0, cut);
}
