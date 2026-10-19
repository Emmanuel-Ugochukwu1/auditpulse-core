import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { FunctionRule } from "../engine.js";
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
 * A statement consisting purely of an authorization check.
 * Handles `env.require_auth(...)`, `account.require_auth()`,
 * `env.require_auth_for_args(...)`, etc.
 */
const AUTH_STMT_REGEX =
  /^(?:[A-Za-z_]\w*\.)?require_auth(?:_for_args)?\s*\([^;]*\)$/;

/**
 * Determines whether a function body consists solely of authorization checks.
 * Returns true if the function has at least one auth check and no non-auth statements.
 */
export function isAuthHelper(fn: ScannedFunction): boolean {
  const clean = sanitizeKeepLines(fn.body);
  const openBrace = clean.indexOf("{");
  const closeBrace = clean.lastIndexOf("}");
  if (openBrace < 0 || closeBrace <= openBrace) {
    return false;
  }

  const inner = clean.slice(openBrace + 1, closeBrace).trim();
  if (!inner || !AUTH_CHECK.test(inner)) {
    return false;
  }

  // Statements separated by semicolon
  const statements = inner
    .split(";")
    .map((s) => s.replace(/\s+/g, " ").trim())
    .filter((s) => s.length > 0);

  if (statements.length === 0) {
    return false;
  }

  for (const stmt of statements) {
    if (!AUTH_STMT_REGEX.test(stmt)) {
      return false;
    }
  }

  return true;
}

/**
 * Finds the earliest invocation of an intra-file auth helper function.
 * Matches `Self::helper(` or `helper(`.
 */
function findFirstHelperAuthCall(
  body: string,
  authHelpers: readonly string[],
): number | null {
  if (authHelpers.length === 0) {
    return null;
  }
  const escaped = authHelpers.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const pattern = new RegExp(`\\b(?:Self::)?(?:${escaped.join("|")})\\s*\\(`, "g");
  const match = pattern.exec(body);
  return match ? match.index : null;
}

export class MissingRequireAuthPlugin implements Rule, FunctionRule {
  id = "AP-AUTH-001";
  name = "Missing Require Auth";
  description =
    "Detects authorization-sensitive operations (token transfers, balance updates, ledger entry writes) in functions that never call env.require_auth()";

  scan(code: string): Vulnerability[] {
    const fns = extractRustFunctions(sanitizeKeepLines(code));
    return fns.flatMap((fn) => this.scanFunction(fn, fns));
  }

  /**
   * The engine passes functions extracted from raw source; comments and
   * string contents are blanked here so only executable text is judged.
   *
   * Ordering matters: an auth check only gates operations that execute
   * after it. When the first sensitive operation appears before the first
   * require_auth (or intra-file auth helper call) in the body, the operation
   * runs unauthorized and the finding survives. A trailing check does not
   * retroactively gate it.
   */
  scanFunction(
    fn: ScannedFunction,
    allFunctions?: readonly ScannedFunction[],
  ): Vulnerability[] {
    const clean = sanitizeKeepLines(fn.body);
    const brace = clean.indexOf("{");
    const body = brace >= 0 ? clean.slice(brace) : clean;

    const sensitive = SENSITIVE_OP.exec(body);
    if (!sensitive) {
      return [];
    }

    const auth = AUTH_CHECK.exec(body);
    const directAuthIndex = auth ? auth.index : Infinity;

    const authHelpers = (allFunctions ?? [])
      .filter((f) => f.name !== fn.name && isAuthHelper(f))
      .map((f) => f.name);

    const helperAuthIndex = findFirstHelperAuthCall(body, authHelpers) ?? Infinity;

    const earliestAuthIndex = Math.min(directAuthIndex, helperAuthIndex);
    if (earliestAuthIndex < sensitive.index) {
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
