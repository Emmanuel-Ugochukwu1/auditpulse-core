import fs from "fs";
import path from "path";
import { AuditEngine } from "./engine.js";
import type { RuleId, Severity, SourceLocation, Vulnerability } from "./types";
import type { AuditPulseConfig } from "./config";
import { SEVERITY_ORDER, findConfigFile, parseConfig, resolveConfig } from "./config.js";
import { discoverRustFiles } from "./workspace.js";

/**
 * Scans a single file or a whole directory tree with the existing engine,
 * applies configuration filtering, and returns per-file findings.
 *
 * Every file is scanned independently; there is no cross-file dataflow.
 */
export interface FileFinding extends Vulnerability {
  /**
   * Path of the finding's file, relative to the current working directory
   * when the file lives under it (otherwise absolute), always with forward
   * slashes so the value is directly usable in SARIF/JSON output.
   */
  file: string;
}

export interface ScanReport {
  /** Path exactly as given on the command line. */
  target: string;
  findings: FileFinding[];
  /** Number of Rust files examined (1 for single-file scans). */
  filesScanned: number;
}

/**
 * Loads configuration for a scan target: auditpulse.toml is looked up in the
 * target directory (or its parents). Returns the config plus the path it came
 * from, or null when no file exists (defaults apply).
 */
export function loadConfig(
  targetPath: string,
  knownRuleIds: RuleId[],
  readFile: (path: string) => string | null = readOrNull,
): { config: AuditPulseConfig; path: string | null } {
  const configPath = findConfigFile(targetPath, readFile);
  if (configPath === null) {
    return { config: resolveConfig({}, knownRuleIds), path: null };
  }

  const parsed = parseConfig(readFile(configPath) ?? "");
  return { config: resolveConfig(parsed, knownRuleIds), path: configPath };
}

/**
 * Scans `target` (a file or directory) and returns a report. Throws
 * InputError when the path does not exist or is not a file/directory.
 */
export function scanTarget(
  target: string,
  engine: AuditEngine,
  config: AuditPulseConfig,
): ScanReport {
  if (!fs.existsSync(target)) {
    throw new InputError(`Path not found: ${target}`);
  }

  const stat = fs.statSync(target);
  if (stat.isFile()) {
    if (!target.endsWith(".rs")) {
      throw new InputError(`Not a Rust source file: ${target}`);
    }
    // Report the file under its display path (cwd-relative when possible) so
    // SARIF consumers such as GitHub Code Scanning can resolve locations.
    const findings = scanFile("", toDisplayPath(target), engine, config);
    return { target, findings, filesScanned: 1 };
  }

  if (!stat.isDirectory()) {
    throw new InputError(`Not a file or directory: ${target}`);
  }

  const displayRoot = toDisplayPath(target);
  const files = discoverRustFiles(target, config.exclude);
  const findings: FileFinding[] = [];
  for (const relPath of files) {
    // Forward-slash join: relPath is already forward-slashed (posix-style).
    const displayPath = displayRoot === "" ? relPath : `${displayRoot}/${relPath}`;
    findings.push(...scanFile(target, relPath, engine, config, displayPath));
  }

  return { target, findings, filesScanned: files.length };
}

/**
 * Path used in findings: relative to the current working directory when the
 * target lives under it ("" when the target *is* the working directory),
 * otherwise the resolved absolute path. Forward slashes throughout.
 */
function toDisplayPath(target: string): string {
  let abs: string;
  try {
    abs = fs.realpathSync(target);
  } catch {
    abs = path.resolve(target);
  }

  let cwd: string;
  try {
    cwd = fs.realpathSync(process.cwd());
  } catch {
    cwd = process.cwd();
  }

  const rel = path.relative(cwd, abs);
  if (!rel.startsWith("..") && !path.isAbsolute(rel)) {
    return rel.split(path.sep).join("/");
  }
  return abs.split(path.sep).join("/");
}

export function parseSuppressions(code: string): Map<number, Set<string>> {
  const map = new Map<number, Set<string>>();
  const lines = code.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const match = /\bauditpulse-ignore\s+([A-Za-z0-9_, -]+)/.exec(line);
    if (!match) continue;

    const rawIds = match[1] ?? "";
    const ruleIds = rawIds
      .split(/[\s,]+/)
      .map((id) => id.trim())
      .filter((id) => id.length > 0);

    if (ruleIds.length === 0) continue;

    const currentLine = i + 1;
    const nextLine = i + 2;

    let setCurr = map.get(currentLine);
    if (!setCurr) {
      setCurr = new Set();
      map.set(currentLine, setCurr);
    }
    for (const id of ruleIds) setCurr.add(id);

    let setNext = map.get(nextLine);
    if (!setNext) {
      setNext = new Set();
      map.set(nextLine, setNext);
    }
    for (const id of ruleIds) setNext.add(id);
  }

  return map;
}

export function isSuppressed(
  finding: Vulnerability,
  suppressions: Map<number, Set<string>>,
): boolean {
  const line = finding.location.line;
  const set = suppressions.get(line);
  return set !== undefined && set.has(finding.id);
}

/** Scans one file and attaches its display path to every finding. */
function scanFile(
  root: string,
  relPath: string,
  engine: AuditEngine,
  config: AuditPulseConfig,
  displayPath: string = relPath,
): FileFinding[] {
  const code = fs.readFileSync(path.join(root, relPath), "utf-8");
  const suppressions = parseSuppressions(code);
  const findings: FileFinding[] = [];

  // One pass over the file: the engine parses it once (or falls back to
  // source-text extraction) and hands every rule the same structure, so no
  // rule re-parses or re-extracts on its own. Disabled rules never run;
  // inline suppressions and severity overrides are applied before minSeverity
  // threshold filtering.
  for (let finding of engine.run(code, { disabledRules: config.disabledRules })) {
    if (isSuppressed(finding, suppressions)) {
      continue;
    }
    const override = config.severityOverrides[finding.id];
    if (override !== undefined) {
      finding = { ...finding, severity: override };
    }
    if (SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[config.minSeverity]) {
      continue;
    }
    findings.push({ ...finding, file: displayPath });
  }

  return sortFindings(findings);
}

/** Deterministic order: file path, then line, then rule id. */
export function sortFindings(findings: FileFinding[]): FileFinding[] {
  return [...findings].sort((a, b) => {
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    if (a.location.line !== b.location.line) return a.location.line - b.location.line;
    if (a.id !== b.id) return a.id < b.id ? -1 : 1;
    return compareMessages(a, b);
  });
}

function compareMessages(a: FileFinding, b: FileFinding): number {
  if (a.message === b.message) return 0;
  return a.message < b.message ? -1 : 1;
}

/** Error for bad user input: wrong path type, missing file, etc. */
export class InputError extends Error {}

function readOrNull(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}

/**
 * Only reports column/function when the plugin provided them; here we expose
 * the location untouched so unreliable data is never invented.
 */
export function locationOf(finding: FileFinding): SourceLocation {
  return finding.location;
}
