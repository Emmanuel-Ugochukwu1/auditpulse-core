import type { Rule, Vulnerability } from "../types";
import { extractRustFunctions, removeComments } from "../utils/rust.js";

/**
 * Recognizable administrative/upgrade entrypoints. Only function names in
 * this list are considered — ordinary state-changing functions are not
 * flagged just because they write storage.
 */
const ADMIN_FUNCTION_NAME =
  /\b(?:upgrade|set_upgrade|deploy|install|migrate|set_admin|transfer_admin|change_admin|set_operator|set_fee|set_treasury|set_owner|set_pauser)\b/i;

/**
 * Evidence that the function is gated: an explicit auth check or an
 * admin-identity read that is compared/returned. `read_authority` alone
 * without require_auth is NOT accepted as a boundary.
 */
const AUTHORIZATION_CHECK =
  /require_auth(?:_for_args)?\s*\(|\bhas_admin\b|\bis_admin\b|\bassert_admin\b|\bcheck_admin\b|\bonly_admin\b|\bowner_check\b|\bverify_admin\b/i;

/**
 * AP-UPG-001 — flags upgrade/admin-sensitive functions that contain no
 * recognizable authorization check. Detection is deliberately name-based so
 * ordinary state-changing functions are never reported.
 */
export class UnprotectedUpgradePlugin implements Rule {
  id = "AP-UPG-001";
  name = "Unprotected Upgrade";
  description =
    "Detects upgrade, migration, and admin-configuration functions that perform privileged changes without an obvious require_auth or admin check";

  scan(code: string): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const fns = extractRustFunctions(removeComments(code));

    for (const fn of fns) {
      if (!ADMIN_FUNCTION_NAME.test(fn.name)) {
        continue;
      }
      if (AUTHORIZATION_CHECK.test(fn.analysisBodyInner)) {
        continue;
      }

      findings.push({
        id: "AP-UPG-001",
        message: `Function '${fn.name}' appears to upgrade or reconfigure the contract but contains no require_auth or admin check. Anyone able to invoke it could replace or reconfigure the contract.`,
        severity: "critical",
        confidence: "medium",
        location: { line: fn.line, function: fn.name },
        remediation:
          "Gate the function behind an explicit authorization check, e.g. env.require_auth(&admin) after loading the stored admin, and emit an event for the administrative change.",
      });
    }

    return findings;
  }
}

export default new UnprotectedUpgradePlugin();
