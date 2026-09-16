import type { Rule, Vulnerability } from "../types";
import { extractRustFunctions, removeComments } from "../utils/rust.js";

export class MissingExtendTtlPlugin implements Rule {
  id = "AP-STORAGE-001";
  name = "Missing Extend TTL";
  description =
    "Detects ledger storage access (persistent/temporary instance storage) that is never accompanied by an extend_ttl call, which risks silent data expiry";

  scan(code: string): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const clean = removeComments(code);
    const functions = extractRustFunctions(clean);
    const storage = /storage\s*\(\s*\)\s*\./;

    // Macro definitions are declarations, not executed code. Only function
    // bodies plus local macro bodies actually invoked by those functions count.
    const storageFunction = functions.find((fn) => storage.test(fn.analysisBody));
    if (storageFunction === undefined) {
      return findings;
    }

    const macroAwareFunctions = functions.map((fn) => fn.analysisBody).join("\n");
    const extended =
      /\.extend_ttl\s*\(/.test(macroAwareFunctions) ||
      /extend_ttl_to_threshold\s*\(/.test(macroAwareFunctions) ||
      /get_extended\s*\(/.test(macroAwareFunctions);
    if (extended) {
      return findings;
    }

    const bodyLines = storageFunction.body.split("\n");
    const bodyLine = bodyLines.findIndex((value) => storage.test(value));
    const line = bodyLine >= 0 ? storageFunction.line + bodyLine : storageFunction.line;
    if (line >= 1) {
      findings.push({
        id: "AP-STORAGE-001",
        message:
          "Ledger entries accessed here are never bumped via extend_ttl; expired persistent/temporary entries read back as None. Add env.storage().extend_ttl(...) to keep required entries alive.",
        severity: "high",
        confidence: "medium",
        location: {
          line,
          function: storageFunction.name,
        },
        remediation:
          "After reading or writing persistent/temporary storage, call env.storage().persistent().extend_ttl(&key, threshold, extend_to) or extend_ttl_to_threshold to keep entries alive.",
      });
    }

    return findings;
  }
}

export default new MissingExtendTtlPlugin();
