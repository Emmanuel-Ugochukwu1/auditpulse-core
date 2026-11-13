import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { FunctionRule } from "../engine.js";
import {
  extractRustFunctions,
  functionLocation,
  hasAuthAttribute,
  macrosContaining,
  sanitizeKeepLines,
} from "../utils/rust.js";

/**
 * Authorization-sensitive operations (token transfers, balance updates,
 * ledger entry writes) whose exposure matters for AP-AUTH-001.
 */
const SENSITIVE_OP =
  /client\.|\btransfer\b|\btransfer_from\b|\bburn\b|\bbump_arc\b|\bput_arc\b|\bdel_arc\b|\bget_arc\b|\.set\s*\(/;

/** An explicit authorization check inside the function body. */
const AUTH_CHECK = /require_auth(?:_for_args)?\s*\(|assert_auth!\s*\(|auth_check!\s*\(/;

export class MissingRequireAuthPlugin implements Rule, FunctionRule {
  id = "AP-AUTH-001";
  name = "Missing Require Auth";
  description =
    "Detects authorization-sensitive operations (token transfers, balance updates, ledger entry writes) in functions that never call env.require_auth()";

  scan(code: string): Vulnerability[] {
    return extractRustFunctions(sanitizeKeepLines(code)).flatMap((fn) =>
      this.scanFunction(fn, code),
    );
  }

  /**
   * Scans a function for authorization boundaries.
   *
   * Now recognizes:
   * 1. Procedural attribute macros (e.g. `#[only_owner]`, `#[only_admin]`, `#[require_auth]`).
   * 2. Local `macro_rules!` expansions that wrap `require_auth` or authorization checks.
   */
  scanFunction(fn: ScannedFunction, fileCode?: string): Vulnerability[] {
    // 1. Procedural attribute macros preceding the function
    if (hasAuthAttribute(fn)) {
      return [];
    }

    const clean = sanitizeKeepLines(fn.body);
    const brace = clean.indexOf("{");
    const body = brace >= 0 ? clean.slice(brace) : clean;

    const sensitive = SENSITIVE_OP.exec(body);
    if (!sensitive) {
      return [];
    }

    // 2. Local macro_rules! whose body calls require_auth
    const macros = fileCode === undefined ? [] : macrosContaining(fileCode, AUTH_CHECK);
    const authPattern =
      macros.length === 0
        ? AUTH_CHECK
        : new RegExp(`${AUTH_CHECK.source}|\\b(?:${macros.join("|")})\\s*!\\s*[(\\[{]`);

    const auth = authPattern.exec(body);
    if (auth && auth.index < sensitive.index) {
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
