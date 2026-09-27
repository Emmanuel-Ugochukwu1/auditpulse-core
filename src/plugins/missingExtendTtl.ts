import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { AstAwareRule } from "../engine.js";
import { locateLine, removeCommentsKeepLines } from "../utils/rust.js";

/**
 * Blanks string/char literal contents for the TTL check. Matching is
 * line-scoped on purpose: an unpaired apostrophe on a line is a Rust
 * lifetime (`&'a`, `<'a>`), not a literal opener, so it must not start a
 * span that swallows following lines. Literals that genuinely span
 * multiple lines are therefore not blanked — a documented limitation.
 */
function blankLiteralsPerLine(code: string): string {
  const literal = /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g;
  return code
    .split("\n")
    .map((line) =>
      line.replace(literal, (match) => match.replace(/[^"'\n]/g, " ")),
    )
    .join("\n");
}

const STORAGE_CHAIN = /storage\s*\(\s*\)\s*\./;
const STORAGE_CALL = /storage\s*\(\s*\)/;
const TTL_BUMP =
  /\.extend_ttl\s*\(|extend_ttl_to_threshold\s*\(|get_extended\s*\(/;

export class MissingExtendTtlPlugin implements Rule, AstAwareRule {
  id = "AP-STORAGE-001";
  name = "Missing Extend TTL";
  description =
    "Detects ledger storage access (persistent/temporary instance storage) that is never accompanied by an extend_ttl call, which risks silent data expiry";

  scan(code: string): Vulnerability[] {
    return this.scanCode(code, null);
  }

  /**
   * The rule is file-level: one finding when storage is accessed without
   * any extend_ttl in the file. Comment and string-literal contents are
   * not executable code, so they count for neither side of the check. The
   * reported line is where the first access chain begins (its `storage()`
   * call), so chains formatted across multiple lines still anchor where
   * the developer sees the access; with the shared AST extraction
   * available, the enclosing function and its fn-keyword column are
   * attached.
   */
  scanCode(code: string, functions: ScannedFunction[] | null): Vulnerability[] {
    const clean = blankLiteralsPerLine(removeCommentsKeepLines(code));

    if (!STORAGE_CHAIN.test(clean)) {
      return [];
    }

    if (TTL_BUMP.test(clean)) {
      return [];
    }

    const line = clean
      .split("\n")
      .findIndex((value) => STORAGE_CALL.test(value));
    if (line >= 0) {
      return [
        {
          id: "AP-STORAGE-001",
          message:
            "Ledger entries accessed here are never bumped via extend_ttl; expired persistent/temporary entries read back as None. Add env.storage().extend_ttl(...) to keep required entries alive.",
          severity: "high",
          confidence: "medium",
          location: locateLine(functions, line + 1),
          remediation:
            "After reading or writing persistent/temporary storage, call env.storage().persistent().extend_ttl(&key, threshold, extend_to) or extend_ttl_to_threshold to keep entries alive.",
        },
      ];
    }

    return [];
  }
}

export default new MissingExtendTtlPlugin();
