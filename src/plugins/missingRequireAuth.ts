import type { Rule, Vulnerability } from "../types";
import { extractRustFunctions, sanitizeKeepLines } from "../utils/rust.js";

export class MissingRequireAuthPlugin implements Rule {
  id = "AP-AUTH-001";
  name = "Missing Require Auth";
  description =
    "Detects authorization-sensitive operations (token transfers, balance updates, ledger entry writes) in functions that never call env.require_auth()";

  scan(code: string): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const fns = extractRustFunctions(sanitizeKeepLines(code));

    for (const fn of fns) {
      const body = fn.analysisBody;
      const sensitive =
        /client\.|\btransfer\b|\btransfer_from\b|\bburn\b|\bbump_arc\b|\bput_arc\b|\bdel_arc\b|\bget_arc\b|\.set\s*\(/.test(
          body,
        );
      if (!sensitive) {
        continue;
      }

      const authorized = /require_auth(?:_for_args)?\s*\(/.test(body);
      if (!authorized) {
        const name = /\bfn\s+(\w+)\s*\(/.exec(fn.body)?.[1] ?? "<anonymous>";
        findings.push({
          id: "AP-AUTH-001",
          message: `Authorization-sensitive operations in function '${name}' are not gated by require_auth. Add env.require_auth(&...) so only the intended account can invoke it.`,
          severity: "critical",
          confidence: "high",
          location: {
            line: fn.line,
            function: name,
          },
          remediation:
            "Add env.require_auth(&account) for the account authorized to perform the sensitive operation.",
        });
      }
    }

    return findings;
  }
}

export default new MissingRequireAuthPlugin();
