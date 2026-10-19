import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { FunctionRule } from "../engine.js";
import { extractRustFunctions, functionLocation, removeComments } from "../utils/rust.js";

/**
 * Entrypoint shapes typically responsible for depositing, withdrawing,
 * minting, burning, or transferring funds.
 */
const BOUNDED_ENTRYPOINTS = /\b(?:deposit|withdraw|mint|burn|transfer)\b/i;

/** Amount-like parameters or identifiers representing transfer value. */
const AMOUNT_IDENTIFIER = /\b(?:amount|amt|value|shares|tokens)\b/i;

/** Evidence that the function moves or mutates an amount in storage or balances. */
const AMOUNT_MOVEMENT =
  /\bbalances?\b[\s\S]*?\.set\(|\.set\s*\(\s*&(?:user|from|to|account|holder|address)\b|\b(?:balance|total_supply|shares?|pool)\s*(?:[\+\-]=|[\+\-]\s*(?:amount|amt|value))|\b(?:balance|updated|new_bal|new_balance)\s*=\s*.*(?:amount|amt|value)/i;

/** Evidence of positivity or bound assertions protecting the amount. */
const BOUNDS_ASSERTION =
  /\b(?:assert|assert_ne|assert_gt|assert_ge|require)!\s*\(|\bif\b[^{;]+(?:<=?|>=?|==|!=)|\.(?:min|max|clamp)\s*\(|\.checked_(?:sub|add)\s*\(|\bok_or\s*\(/i;

/**
 * AP-BOUND-001 — flags deposit/withdraw-shaped entrypoints that move an
 * amount-like value without any bound or positivity assertion.
 *
 * Severity: low, Confidence: low (hygiene signal, prefers silence over noise).
 */
export class UnvalidatedAmountBoundsPlugin implements Rule, FunctionRule {
  id = "AP-BOUND-001";
  name = "Unvalidated Amount Bounds";
  description =
    "Detects deposit, withdraw, mint, burn, or transfer entrypoints that adjust balances without asserting that the amount is strictly positive or bounded";

  scan(code: string): Vulnerability[] {
    return extractRustFunctions(removeComments(code)).flatMap((fn) =>
      this.scanFunction(fn),
    );
  }

  scanFunction(fn: ScannedFunction): Vulnerability[] {
    if (!BOUNDED_ENTRYPOINTS.test(fn.name)) {
      return [];
    }

    const clean = removeComments(fn.bodyInner);
    if (!AMOUNT_IDENTIFIER.test(fn.body)) {
      return [];
    }

    if (!AMOUNT_MOVEMENT.test(clean)) {
      return [];
    }

    if (BOUNDS_ASSERTION.test(clean)) {
      return [];
    }

    return [
      {
        id: this.id,
        message: `Entrypoint function '${fn.name}' moves an amount-like value without an explicit bound or positivity check (e.g. assert!(amount > 0)).`,
        severity: "low",
        confidence: "low",
        location: functionLocation(fn),
        remediation:
          "Assert that the amount is strictly positive and within valid bounds (e.g. assert!(amount > 0) or require!(amount > 0)) before updating balances.",
      },
    ];
  }
}

export default new UnvalidatedAmountBoundsPlugin();
