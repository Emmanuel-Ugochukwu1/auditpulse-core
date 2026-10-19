#!/usr/bin/env node
import fs from "fs";
import path from "path";
import { pathToFileURL } from "url";
import { AuditEngine } from "./engine.js";
import { createDefaultRegistry } from "./registry.js";
import type { Severity } from "./types";
import type { AuditPulseConfig } from "./config";
import { MIN_SEVERITIES, parseConfig, resolveConfig } from "./config.js";
import { scanTarget, InputError } from "./scanner.js";
import type { ScanReport } from "./scanner";
import { renderHuman } from "./reporting/human.js";
import { renderJson } from "./reporting/json.js";
import { renderSarif } from "./reporting/sarif.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";

/**
 * AuditPulse command-line interface.
 *
 * Exit codes (documented in README):
 *   0 = no findings at or above the configured severity threshold
 *   1 = findings at or above the threshold
 *   2 = usage/configuration/input error
 */

export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_USAGE = 2;

interface ScanOptions {
  format: "human" | "json" | "sarif";
  minSeverity?: Severity;
  configPath?: string;
}

export function main(argv: string[]): number {
  const [command, ...rest] = argv;
  if (!command || command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return EXIT_OK;
  }

  if (command === "--version" || command === "-v") {
    console.log(`${TOOL_NAME} ${TOOL_VERSION}`);
    return EXIT_OK;
  }

  try {
    switch (command) {
      case "scan":
        return runScan(rest);
      case "report":
        return runScanLike(rest, "human");
      case "sarif":
        return runScanLike(rest, "sarif");
      case "init":
        return runInit(rest);
      default:
        console.error(`Unknown command: ${command}`);
        console.error("Run 'auditpulse help' for usage.");
        return EXIT_USAGE;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Error: ${message}`);
    return EXIT_USAGE;
  }
}

function runScan(args: string[]): number {
  const { options, positional } = parseScanArgs(args);
  if (!positional) {
    console.error(
      "Usage: auditpulse scan <path> [--format human|json|sarif] [--min-severity <level>] [--config <file>]",
    );
    return EXIT_USAGE;
  }

  const engine = new AuditEngine(createDefaultRegistry());
  const config = loadConfig(positional, options, engine);
  const report = scanTarget(positional, engine, config);
  return emit(options.format, report, engine);
}

function runScanLike(args: string[], format: "human" | "sarif"): number {
  const { options, positional } = parseScanArgs(args);
  if (!positional) {
    console.error(`Usage: auditpulse ${format} <path> [--min-severity <level>] [--config <file>]`);
    return EXIT_USAGE;
  }

  const engine = new AuditEngine(createDefaultRegistry());
  const config = loadConfig(positional, options, engine);
  const report = scanTarget(positional, engine, config);
  return emit(format, report, engine);
}

function runInit(args: string[]): number {
  let configPath = "auditpulse.toml";
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--config") {
      const value = args[++i];
      if (!value) throw new InputError("--config requires a file path");
      configPath = value;
      continue;
    }
    console.error(`Unexpected argument for init: ${args[i]}`);
    console.error("Usage: auditpulse init [--config <file>]");
    return EXIT_USAGE;
  }

  if (fs.existsSync(configPath)) {
    console.error(`Error: ${configPath} already exists`);
    return EXIT_USAGE;
  }

  fs.writeFileSync(
    configPath,
    [
      "# AuditPulse configuration (all keys optional)",
      '# disabled_rules = ["AP-DEBUG-001"]',
      '# min_severity = "low"  # low | medium | high | critical',
      '# exclude = ["vendor", "generated"]',
      "",
      "# [severity_overrides]",
      '# "AP-ARITH-001" = "critical"',
      "",
    ].join("\n"),
  );
  console.log(`Created ${configPath}`);
  return EXIT_OK;
}

/** Shared flag parsing for scan/report/sarif. */
function parseScanArgs(args: string[]): {
  options: ScanOptions;
  positional: string | null;
} {
  const options: ScanOptions = { format: "human" };
  let positional: string | null = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? "";
    switch (arg) {
      case "--format": {
        const value = args[++i];
        if (value !== "human" && value !== "json" && value !== "sarif") {
          throw new InputError(
            `--format must be human, json, or sarif, got: ${value ?? "(missing)"}`,
          );
        }
        options.format = value;
        break;
      }
      case "--min-severity": {
        const value = args[++i];
        if (!value || !MIN_SEVERITIES.includes(value as Severity)) {
          throw new InputError(
            `--min-severity must be one of ${MIN_SEVERITIES.join(", ")}, got: ${value ?? "(missing)"}`,
          );
        }
        options.minSeverity = value as Severity;
        break;
      }
      case "--config": {
        const value = args[++i];
        if (!value) throw new InputError("--config requires a file path");
        options.configPath = value;
        break;
      }
      default:
        if (arg.startsWith("--")) {
          throw new InputError(`Unknown option: ${arg}`);
        }
        if (positional !== null) {
          throw new InputError(`Unexpected extra argument: ${arg}`);
        }
        positional = arg;
        break;
    }
  }

  return { options, positional };
}

/**
 * Resolves configuration for a scan: --config wins, else the nearest
 * auditpulse.toml up from the target, else defaults. A --min-severity flag
 * overrides whatever the config set.
 */
function loadConfig(
  target: string,
  options: ScanOptions,
  engine: AuditEngine,
): AuditPulseConfig {
  const knownRuleIds = engine.rules().map((rule) => rule.id);
  const configPath = options.configPath ?? findNearestConfig(target);
  if (configPath === null) {
    return withOverride(resolveConfig({}, knownRuleIds));
  }
  if (!fs.existsSync(configPath)) {
    throw new InputError(`Config file not found: ${configPath}`);
  }

  const parsed = parseConfig(fs.readFileSync(configPath, "utf-8"));
  return withOverride(resolveConfig(parsed, knownRuleIds));

  function withOverride(config: AuditPulseConfig): AuditPulseConfig {
    return options.minSeverity ? { ...config, minSeverity: options.minSeverity } : config;
  }
}

function findNearestConfig(target: string): string | null {
  let dir =
    fs.existsSync(target) && fs.statSync(target).isDirectory()
      ? target
      : path.dirname(target);
  for (;;) {
    const candidate = path.join(dir, "auditpulse.toml");
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function emit(
  format: "human" | "json" | "sarif",
  report: ScanReport,
  engine: AuditEngine,
): number {
  switch (format) {
    case "json":
      console.log(renderJson(report));
      break;
    case "sarif":
      console.log(renderSarif(report, { ruleDescriptions: ruleDescriptions(engine) }));
      break;
    default:
      console.log(renderHuman(report));
      break;
  }
  // Threshold filtering already happened during the scan; any surviving
  // finding means the scan "failed" from a CI perspective.
  return report.findings.length > 0 ? EXIT_FINDINGS : EXIT_OK;
}

function ruleDescriptions(engine: AuditEngine): Map<string, string> {
  return new Map(engine.rules().map((rule) => [rule.id, rule.description]));
}

function printHelp(): void {
  console.log(
    `${TOOL_NAME} ${TOOL_VERSION} - static security scanner for Soroban (Rust) smart contracts

Usage:
  auditpulse scan <path>        Scan a Rust file or a directory tree
  auditpulse report <path>      Scan and print the human-readable report
  auditpulse sarif <path>       Scan and print SARIF 2.1.0 output
  auditpulse init               Write a starter auditpulse.toml in the current directory
  auditpulse help               Show this help

Options:
  --format human|json|sarif     Output format for scan (default: human)
  --min-severity <level>        Drop findings below this severity (low, medium, high, critical)
  --config <file>               Path to auditpulse.toml (default: nearest auditpulse.toml, else defaults)

Exit codes:
  0 = no findings at or above the configured threshold
  1 = findings at or above the threshold
  2 = usage, configuration, or input error`,
  );
}

// Run when executed directly; importing this module (e.g. in tests) is side-effect free.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
