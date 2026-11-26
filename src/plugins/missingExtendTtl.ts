import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { AstAwareRule } from "../engine.js";
import { locateLine, sanitizeKeepLines } from "../utils/rust.js";

type StorageKind = "persistent" | "temporary" | "instance";

interface StorageCall {
  kind: StorageKind;
  method: string;
  key: string;
  index: number;
}

const STORAGE_CALL =
  /\.storage\s*\(\s*\)\s*\.\s*(persistent|temporary|instance)\s*\(\s*\)\s*\.\s*([A-Za-z_]\w*)\s*\(/g;

const REQUIRES_TTL = new Set([
  "get",
  "set",
  "try_get",
  "try_update",
  "update",
]);

const EXTENDS_TTL = new Set([
  "extend_ttl",
  "extend_ttl_to_threshold",
  "get_extended",
]);

/** Reads one Rust call argument while respecting nested delimiters. */
function firstArgument(code: string, start: number): string {
  let depth = 0;
  for (let index = start; index < code.length; index++) {
    const char = code[index];
    if (char === "(" || char === "[" || char === "{") {
      depth++;
      continue;
    }
    if (char === "]" || char === "}") {
      depth--;
      continue;
    }
    if (char === ")") {
      if (depth === 0) return code.slice(start, index);
      depth--;
      continue;
    }
    if (char === "," && depth === 0) {
      return code.slice(start, index);
    }
  }
  return "";
}

function normalizeKey(key: string): string {
  return key.trim().replace(/\.clone\s*\(\s*\)/g, "").replace(/\s+/g, "").replace(/^&+/, "");
}

function isBareIdentifier(key: string): boolean {
  return /^[A-Za-z_]\w*$/.test(key);
}

function coverageKey(kind: StorageKind, key: string): string {
  return `${kind}:${key}`;
}

export class MissingExtendTtlPlugin implements Rule, AstAwareRule {
  id = "AP-STORAGE-001";
  name = "Missing Extend TTL";
  description =
    "Detects ledger storage access (persistent/temporary instance storage) that is never accompanied by an extend_ttl call, which risks silent data expiry";

  scan(code: string): Vulnerability[] {
    return this.scanCode(code, null);
  }

  /**
   * A valid extension must target the same storage kind and entry as the
   * access. To avoid false positives for keys resolved into a local variable,
   * a bare-identifier extension key is treated as covering that storage kind.
   * We keep the established one-finding-per-file contract and report the
   * earliest uncovered access, rather than letting an unrelated extension hide
   * every other entry in the file.
   */
  scanCode(code: string, functions: ScannedFunction[] | null): Vulnerability[] {
    // Comments and string literals must not be able to satisfy the TTL check.
    const clean = sanitizeKeepLines(code);
    const calls: StorageCall[] = [];

    for (const match of clean.matchAll(STORAGE_CALL)) {
      const kind = match[1] as StorageKind;
      const method = match[2] ?? "";
      const index = match.index ?? 0;
      const key =
        kind === "instance"
          ? "@instance"
          : normalizeKey(firstArgument(clean, index + match[0].length));
      calls.push({ kind, method, key, index });
    }

    if (calls.length === 0) {
      return [];
    }

    const extendedKeys = new Set<string>();
    const looselyCoveredKinds = new Set<StorageKind>();
    for (const call of calls) {
      if (!EXTENDS_TTL.has(call.method)) continue;
      if (call.kind === "instance") {
        extendedKeys.add(coverageKey(call.kind, call.key));
        continue;
      }
      if (isBareIdentifier(call.key)) {
        looselyCoveredKinds.add(call.kind);
      } else {
        extendedKeys.add(coverageKey(call.kind, call.key));
      }
    }

    const uncovered = calls.find((call) => {
      if (!REQUIRES_TTL.has(call.method)) return false;
      if (call.kind === "instance") {
        return !extendedKeys.has(coverageKey(call.kind, call.key));
      }
      return (
        !looselyCoveredKinds.has(call.kind) &&
        !extendedKeys.has(coverageKey(call.kind, call.key))
      );
    });

    if (uncovered === undefined) {
      return [];
    }

    const line = clean.slice(0, uncovered.index).split("\n").length;
    const entry =
      uncovered.kind === "instance"
        ? "instance storage"
        : `${uncovered.kind} storage entry \`${uncovered.key || "<unknown>"}\``;

    return [
      {
        id: "AP-STORAGE-001",
        message: `Ledger ${entry} is accessed without a matching TTL extension; it can expire while other entries in the file remain live. Add an extend_ttl or extend_ttl_to_threshold call for this entry.`,
        severity: "high",
        confidence: "medium",
        location: locateLine(functions, line),
        remediation:
          "After reading or writing the entry, call env.storage().persistent().extend_ttl(&key, threshold, extend_to), env.storage().temporary().extend_ttl(...), or extend_ttl_to_threshold for the same storage kind and key. Use get_extended when the read should refresh TTL in the same operation.",
      },
    ];
  }
}

export default new MissingExtendTtlPlugin();
