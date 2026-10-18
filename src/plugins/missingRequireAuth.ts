import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { AstAwareRule, FunctionRule } from "../engine.js";
import { extractRustFunctions, functionLocation, sanitizeKeepLines } from "../utils/rust.js";

/**
 * Authorization-sensitive operations (token transfers, balance updates,
 * ledger entry writes) whose exposure matters for AP-AUTH-001.
 */
const SENSITIVE_OP =
  /client\.|\btransfer\b|\btransfer_from\b|\bburn\b|\bbump_arc\b|\bput_arc\b|\bdel_arc\b|\bget_arc\b|\.set\s*\(/;

/** An explicit authorization check inside the function body. */
const AUTH_CHECK = /require_auth(?:_for_args)?\s*\(/;

/**
 * A single statement consisting solely of a require_auth / require_auth_for_args
 * invocation on `env` or an Address receiver.
 */
const PURE_AUTH_STMT =
  /^(?:[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*\s*\.\s*)?require_auth(?:_for_args)?\s*\([\s\S]*\)$/;

/**
 * Builds a shallow intra-file set of helper function names whose bodies
 * consist solely of authorization checks.
 */
export function collectAuthHelpers(functions: readonly ScannedFunction[]): Set<string> {
  const helpers = new Set<string>();
  for (const fn of functions) {
    if (isPureAuthHelper(fn)) {
      helpers.add(fn.name);
    }
  }
  return helpers;
}

function isPureAuthHelper(fn: ScannedFunction): boolean {
  const clean = sanitizeKeepLines(fn.body);
  const open = clean.indexOf("{");
  const close = clean.lastIndexOf("}");
  if (open < 0 || close <= open) {
    return false;
  }
  const inner = clean.slice(open + 1, close).trim();
  if (inner === "") {
    return false;
  }
  const statements = inner
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (statements.length === 0) {
    return false;
  }
  return statements.every(
    (stmt) => PURE_AUTH_STMT.test(stmt) && !SENSITIVE_OP.test(stmt),
  );
}

function findEarliestHelperAuthIndex(
  body: string,
  callerName: string,
  authHelpers: ReadonlySet<string>,
): number | null {
  let earliest: number | null = null;
  for (const helper of authHelpers) {
    if (helper === callerName) continue;
    const escaped = helper.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const callPattern = new RegExp(
      `(?:^|[^.\\w])(?:Self\\s*::\\s*)?${escaped}\\s*\\(`,
    );
    const match = callPattern.exec(body);
    if (match) {
      const idx = match.index + (match[0].startsWith(helper) || match[0].startsWith("Self") ? 0 : 1);
      if (earliest === null || idx < earliest) {
        earliest = idx;
      }
    }
  }
  return earliest;
}

export class MissingRequireAuthPlugin implements Rule, FunctionRule, AstAwareRule {
  id = "AP-AUTH-001";
  name = "Missing Require Auth";
  description =
    "Detects authorization-sensitive operations (token transfers, balance updates, ledger entry writes) in functions that never call env.require_auth()";

  scan(code: string): Vulnerability[] {
    return this.scanCode(code, null);
  }

  /**
   * Reuses the shared per-file ScannedFunction extraction from the engine (or
   * falls back to source-text extraction) to build a shallow intra-file map of
   * pure-auth helper functions before scanning each function.
   */
  scanCode(code: string, functions: ScannedFunction[] | null): Vulnerability[] {
    const extracted = functions ?? extractRustFunctions(sanitizeKeepLines(code));
    const authHelpers = collectAuthHelpers(extracted);
    return extracted.flatMap((fn) => this.scanFunction(fn, authHelpers));
  }

  /**
   * The engine passes functions extracted from raw source; comments and
   * string contents are blanked here so only executable text is judged.
   *
   * Ordering matters: an auth check (direct `require_auth` or a call to an
   * intra-file helper whose body consists solely of `require_auth` checks)
   * only gates operations that execute after it.
   */
  scanFunction(
    fn: ScannedFunction,
    authHelpers: ReadonlySet<string> = new Set(),
  ): Vulnerability[] {
    const clean = sanitizeKeepLines(fn.body);
    const brace = clean.indexOf("{");
    const body = brace >= 0 ? clean.slice(brace) : clean;

    const sensitive = SENSITIVE_OP.exec(body);
    if (!sensitive) {
      return [];
    }

    const auth = AUTH_CHECK.exec(body);
    if (auth && auth.index < sensitive.index) {
      return [];
    }

    const helperIdx = findEarliestHelperAuthIndex(body, fn.name, authHelpers);
    if (helperIdx !== null && helperIdx < sensitive.index) {
      return [];
    }

    return [
      {
        id: "AP-AUTH-001",
        message: `Authorization-sensitive operations in function '${fn.name}' are not gated by require_auth before they execute. Add env.require_auth(&...) ahead of the sensitive operation so only the intended account can invoke it.`,
        severity: "critical",
        confidence: "high",
        location: functionLocation(fn),
        remediation:
          "Add env.require_auth(&account) before the sensitive operation, for the account authorized to perform it.",
      },
    ];
  }
}

export default new MissingRequireAuthPlugin();
