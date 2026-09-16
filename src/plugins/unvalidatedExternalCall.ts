import type { Rule, Vulnerability } from "../types";
import { extractRustFunctions, sanitizeKeepLines } from "../utils/rust.js";

/**
 * AP-CALL-001 — flags cross-contract / external invocations that perform a
 * sensitive operation (token movement, admin changes) with no validation or
 * auth boundary between the entrypoint and the call.
 *
 * Conservative: a validated address (`*_id`, `token_id`, `contract_id`) or
 * `env.require_auth()` counts as a boundary. `try_` results are not
 * considered a boundary on their own — callers must still prove the callee.
 */
export class UnvalidatedExternalCallPlugin implements Rule {
  id = "AP-CALL-001";
  name = "Unvalidated External Call";
  description =
    "Detects token-movement or admin-change operations against external token/contract clients where no address validation or require_auth appears in the function";

  scan(code: string): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const fns = extractRustFunctions(sanitizeKeepLines(code));

    for (const fn of fns) {
      const body = fn.analysisBodyInner;
      const sensitive =
        /client\s*\.\s*(?:transfer|transfer_from|burn|mint|clawback|set_authorized|set_admin)\s*\(/.test(
          body,
        ) ||
        /\b(?:transfer|transfer_from|burn|mint|clawback|set_authorized|set_admin)\s*\(/.test(
          body,
        );

      if (!sensitive) {
        continue;
      }

      const hasAuth = /require_auth(?:_for_args)?\s*\(/.test(body);
      const hasValidation =
        /\b(?:\w+_id|token_id|contract_id)\b/.test(body) ||
        /\.try_(?:transfer|burn|mint|clawback|set_authorized|set_admin)/.test(body);

      if (!hasAuth && !hasValidation) {
        findings.push({
          id: "AP-CALL-001",
          message: `Function '${fn.name}' performs a sensitive external/token operation with no address validation or require_auth boundary. Verify the target contract/address is validated before relying on the call.`,
          severity: "high",
          confidence: "low",
          location: { line: fn.line, function: fn.name },
          remediation:
            "Validate the external contract address and its returned values, and gate the operation with env.require_auth(&...), so only authorized parties can trigger the cross-contract interaction.",
        });
      }
    }

    return findings;
  }
}

export default new UnvalidatedExternalCallPlugin();
