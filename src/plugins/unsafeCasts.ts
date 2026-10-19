import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { FunctionRule } from "../engine.js";
import { extractRustFunctions, sanitizeKeepLines } from "../utils/rust.js";

/** Amount-like identifiers that may be attacker- or contract-relevant. */
const AMOUNT_IDENTIFIER =
  /\b(?:amount|amt|balance|balances|supply|total_supply|value|fee|price|deposit|withdraw|stake|unstake|reward|rewards|share|shares|quota|limit|cap)\w*\b/i;

/**
 * Narrowing integer cast pattern: `as` followed by an integer type narrower
 * than Soroban's native 128-bit amount types (i128/u128).
 */
const NARROWING_CAST = /\bas\s+(?:u8|u16|u32|u64|usize|i8|i16|i32|i64|isize)\b/;

/**
 * AP-CAST-001 — flags narrowing integer casts on amount-like values without
 * checked conversions, which silently truncate high bits and can lead to loss of funds.
 */
export class UnsafeCastsPlugin implements Rule, FunctionRule {
  id = "AP-CAST-001";
  name = "Unsafe Integer Cast";
  description =
    "Detects narrowing integer casts on amount-like values without checked conversions, which can silently truncate values";

  scan(code: string): Vulnerability[] {
    return extractRustFunctions(sanitizeKeepLines(code)).flatMap((fn) =>
      this.scanFunction(fn),
    );
  }

  scanFunction(fn: ScannedFunction): Vulnerability[] {
    const clean = sanitizeKeepLines(fn.body);
    const open = clean.indexOf("{");
    const bodyLines = (open >= 0 ? clean.slice(open + 1) : clean).split("\n");

    const findings: Vulnerability[] = [];
    for (let i = 0; i < bodyLines.length; i++) {
      const line = bodyLines[i] ?? "";
      if (!AMOUNT_IDENTIFIER.test(line) || !NARROWING_CAST.test(line)) {
        continue;
      }

      findings.push({
        id: this.id,
        message: `Narrowing integer cast on amount-like value in function '${fn.name}' may truncate high bits. Use checked conversions instead.`,
        severity: "medium",
        confidence: "medium",
        location: {
          line: fn.bodyLine + i,
          column: fn.column,
          function: fn.name,
        },
        remediation:
          "Replace narrowing 'as' casts with checked conversions like 'u64::try_from(...)' or '.try_into()', handling conversion failures explicitly.",
      });
    }

    return findings;
  }
}

export default new UnsafeCastsPlugin();
