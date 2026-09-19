import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { AstAwareRule } from "../engine.js";
import { locateLine, removeCommentsKeepLines } from "../utils/rust.js";

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
   * any extend_ttl in the file. The reported line is the first storage
   * access; with the shared AST extraction available, the enclosing
   * function and its fn-keyword column are attached.
   */
  scanCode(code: string, functions: ScannedFunction[] | null): Vulnerability[] {
    const clean = removeCommentsKeepLines(code);
    const storage = /storage\s*\(\s*\)\s*\./;

    if (!storage.test(clean)) {
      return [];
    }

    const extended =
      /\.extend_ttl\s*\(/.test(clean) ||
      /extend_ttl_to_threshold\s*\(/.test(clean) ||
      /get_extended\s*\(/.test(clean);
    if (extended) {
      return [];
    }

    const line = clean.split("\n").findIndex((value) => storage.test(value));
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
