import fs from "fs";
import { main } from "./cli.js";

// Library surface: the engine, registry, and rules stay importable exactly
// as before, while the executable entry delegates to the CLI.
export { AuditEngine } from "./engine.js";
export { RuleRegistry, createDefaultRegistry } from "./registry.js";
export type { Severity, Confidence, SourceLocation, Vulnerability, Rule, RuleId } from "./types.js";
export { findExpressionLocation, type FindExpressionOptions } from "./parser/rust.js";
export { TOOL_NAME, TOOL_VERSION } from "./version.js";

const argv = process.argv.slice(2);

/**
 * Backwards-compatible entry: the documented command was
 *   npx ts-node src/index.ts <file-path>
 * A bare path-like argument (no subcommand) is therefore scanned directly;
 * anything else goes through the V2 CLI commands (scan, report, sarif, init,
 * help), which also produce the right error for unknown commands.
 */
const first = argv[0];
const isCommand =
  first === undefined ||
  ["scan", "report", "sarif", "init", "help", "--help", "-h", "--version", "-v"].includes(first);

const looksLikePath =
  !isCommand &&
  (first!.endsWith(".rs") ||
    first!.includes("/") ||
    first!.includes("\\") ||
    fs.existsSync(first!));

process.exit(main(looksLikePath ? ["scan", ...argv] : argv));
