import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { FunctionRule } from "../engine.js";
import { extractRustFunctions, functionLocation, removeComments } from "../utils/rust.js";

/**
 * Recognizable administrative/upgrade entrypoints by function name.
 */
const ADMIN_FUNCTION_NAME =
  /\b(?:upgrade|set_upgrade|deploy|install|migrate|set_admin|transfer_admin|change_admin|set_operator|set_fee|set_treasury|set_owner|set_pauser)\b/i;

/**
 * Storage keys and symbols following administrative or contract-upgrade conventions.
 */
const ADMIN_OR_UPGRADE_KEY_PATTERN =
  /\.set\s*\(\s*&[^,;]*?(?:admin|owner|operator|pauser|treasury|governor|authority|wasm|upgrade|executable)\b/i;

/**
 * Direct Soroban contract upgrade SDK calls.
 */
const CONTRACT_UPGRADE_METHOD = /\bupdate_current_contract_wasm\s*\(/i;

/**
 * Types or parameter/variable names indicative of a Soroban WASM hash operand.
 */
const WASM_HASH_TYPE_OR_NAME =
  /(?:BytesN\s*<\s*32\s*>|wasm_hash|new_wasm|code_hash)\b/i;

/**
 * Evidence that the function is gated: an explicit auth check or an
 * admin-identity read that is compared/returned. `read_authority` alone
 * without require_auth is NOT accepted as a boundary.
 */
const AUTHORIZATION_CHECK =
  /require_auth(?:_for_args)?\s*\(|\bhas_admin\b|\bis_admin\b|\bassert_admin\b|\bcheck_admin\b|\bonly_admin\b|\bowner_check\b|\bverify_admin\b/i;

/**
 * Detects structural secondary signals indicating upgrade or admin actions,
 * catching wrapper functions and non-conventional names without flagging
 * ordinary storage writes.
 */
function hasStructuralUpgradeSignal(
  fn: ScannedFunction,
  cleanBodyInner: string,
): boolean {
  // 1. Direct deployer upgrade call: env.deployer().update_current_contract_wasm(...)
  if (CONTRACT_UPGRADE_METHOD.test(cleanBodyInner)) {
    return true;
  }

  // 2. Writing a BytesN<32> / wasm-hash shaped value to storage
  const hasWasmHash = WASM_HASH_TYPE_OR_NAME.test(fn.body);
  const writesStorage = /\.set\s*\(/.test(cleanBodyInner);
  if (hasWasmHash && writesStorage) {
    return true;
  }

  // 3. Writing to storage keys whose names follow admin or upgrade conventions
  if (ADMIN_OR_UPGRADE_KEY_PATTERN.test(cleanBodyInner)) {
    return true;
  }

  return false;
}

/**
 * AP-UPG-001 — flags upgrade/admin-sensitive functions that contain no
 * recognizable authorization check. Detection combines conventional function
 * names with structural signals (wasm-hash storage writes, admin/upgrade keys,
 * and contract upgrade calls) so unusual naming does not evade the check.
 */
export class UnprotectedUpgradePlugin implements Rule, FunctionRule {
  id = "AP-UPG-001";
  name = "Unprotected Upgrade";
  description =
    "Detects upgrade, migration, and admin-configuration functions that perform privileged changes without an obvious require_auth or admin check";

  scan(code: string): Vulnerability[] {
    return extractRustFunctions(removeComments(code)).flatMap((fn) =>
      this.scanFunction(fn),
    );
  }

  /** The engine passes raw functions; comments are stripped before matching. */
  scanFunction(fn: ScannedFunction): Vulnerability[] {
    const cleanBodyInner = removeComments(fn.bodyInner);

    const matchesName = ADMIN_FUNCTION_NAME.test(fn.name);
    const matchesStructure = hasStructuralUpgradeSignal(fn, cleanBodyInner);

    if (!matchesName && !matchesStructure) {
      return [];
    }
    if (AUTHORIZATION_CHECK.test(cleanBodyInner)) {
      return [];
    }

    return [
      {
        id: "AP-UPG-001",
        message: `Function '${fn.name}' appears to upgrade or reconfigure the contract but contains no require_auth or admin check. Anyone able to invoke it could replace or reconfigure the contract.`,
        severity: "critical",
        confidence: "medium",
        location: functionLocation(fn),
        remediation:
          "Gate the function behind an explicit authorization check, e.g. env.require_auth(&admin) after loading the stored admin, and emit an event for the administrative change.",
      },
    ];
  }
}

export default new UnprotectedUpgradePlugin();
