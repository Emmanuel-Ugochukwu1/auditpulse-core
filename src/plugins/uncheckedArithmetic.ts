import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { FunctionRule } from "../engine.js";
import { extractRustFunctions, findExpressionLocation, functionLocation, sanitizeKeepLines } from "../utils/rust.js";

/** Amount-like identifiers that may be attacker- or contract-relevant. */
const AMOUNT_IDENTIFIER =
  /\b(?:amount|amt|balance|balances|supply|total_supply|value|fee|price|deposit|withdraw|stake|unstake|reward|rewards|share|shares|quota|limit|cap)\w*\b/i;

/**
 * Binary-operator-shaped arithmetic: `operand <op> operand` with an operand
 * (word char, `)` or `]`) before the operator and a word char after any
 * `=`/whitespace. This shape deliberately excludes:
 * - `->` return arrows (`-` followed by `>`, not a word char)
 * - dereferences like `*balance` (`*` with no operand on its left)
 * - unary negation like `= -amount` (`=` is not an operand)
 * Compound assignment (`+=`, `-=`, ...) is covered by the optional `=`.
 */
const BINARY_ARITH = /[\w)\]]\s*[+\-*/]\s*=?\s*[\w]/;

/** Checked/bounded math; a line using these is not reported. */
const GUARDED_MATH =
  /\.(?:checked|overflowing)_(?:add|sub|mul|div)\s*\(|\.saturating_(?:add|sub|mul|div)\s*\(|\.min\s*\(|\.max\s*\(|\.clamp\s*\(/;

/**
 * AP-ARITH-001 — flags binary arithmetic on amount-like identifiers with no
 * checked math on the same line. This is a text heuristic over function
 * bodies, not a full AST walk: it prefers silence over noise, so untouched
 * helpers, counters, and bounded constants produce no findings.
 */
export class UncheckedArithmeticPlugin implements Rule, FunctionRule {
  id = "AP-ARITH-001";
  name = "Unchecked Arithmetic";
  description =
    "Detects add/subtract/multiply/divide on amount-like values (amounts, balances, supplies, fees) without checked math, which can overflow, underflow, or divide by zero";

  scan(code: string): Vulnerability[] {
    // Sanitized input: comments and string contents blanked but line
    // structure preserved, so line numbers stay correct.
    return extractRustFunctions(sanitizeKeepLines(code)).flatMap((fn) =>
      this.scanFunction(fn),
    );
  }

  /** The engine passes raw functions; sanitize to keep line numbers honest. */
  scanFunction(fn: ScannedFunction): Vulnerability[] {
    const clean = sanitizeKeepLines(fn.body);
    // The signature is skipped (generic bounds like `T: Add + Sub` are not
    // arithmetic), so realign body lines through the opening brace. The
    // brace line is known from the extraction, so no re-scan is needed.
    const open = clean.indexOf("{");
    const bodyLines = (open >= 0 ? clean.slice(open + 1) : clean).split("\n");

    const findings: Vulnerability[] = [];
    let lineStartOffset = 0;
    for (let i = 0; i < bodyLines.length; i++) {
      const line = bodyLines[i] ?? "";
      if (!AMOUNT_IDENTIFIER.test(line) || !BINARY_ARITH.test(line)) {
        lineStartOffset += line.length + 1;
        continue;
      }
      if (GUARDED_MATH.test(line)) {
        lineStartOffset += line.length + 1;
        continue;
      }

      const match = BINARY_ARITH.exec(line);
      const opRel = match ? match[0].search(/[+\-*/]/) : -1;
      const opInLine = match && opRel >= 0 ? match.index + opRel : (match?.index ?? 0);
      const exprOffset = lineStartOffset + opInLine;
      const exprLoc = findExpressionLocation(fn, exprOffset);

      findings.push({
        id: "AP-ARITH-001",
        message: `Function '${fn.name}' performs unchecked arithmetic on an amount-like value: verify it cannot overflow, underflow, or divide by zero.`,
        severity: "medium",
        confidence: "medium",
        location: {
          line: fn.bodyLine + i,
          ...(exprLoc !== null ? { column: exprLoc.column } : {}),
          function: fn.name,
        },
        remediation:
          "Use checked math and handle the error explicitly, e.g. balance.checked_sub(amount).ok_or(Error::Underflow)?; prefer checked_add/checked_sub over + and - for i128/u64 amounts.",
      });

      lineStartOffset += line.length + 1;
    }

    return findings;
  }
}

export default new UncheckedArithmeticPlugin();
