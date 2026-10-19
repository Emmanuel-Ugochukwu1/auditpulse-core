import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { FunctionRule } from "../engine.js";
import { extractRustFunctions, findExpressionLocation, functionLocation, sanitizeKeepLines } from "../utils/rust.js";

/**
 * AP-CALL-001 — flags cross-contract / external invocations that perform a
 * sensitive operation (token movement, admin changes) with no validation or
 * auth boundary between the entrypoint and the call.
 *
 * Tiered local validation model, strongest evidence first (each call is
 * judged positionally: only evidence that appears BEFORE the call can gate
 * it):
 *
 * 1. `env.require_auth()` anywhere in the function suppresses the finding
 *    (presence-based; AP-AUTH-001 owns the late-auth ordering problem and
 *    this rule must not double-report the same root cause).
 * 2. An explicit check on an id-bearing value before the call — `assert!`/
 *    `require!` or an equality/inequality comparison on the same line as
 *    the id — suppresses the finding.
 * 3. A user-supplied `*_id` parameter with no visible check is reported at
 *    medium confidence: the argument NAME is a convention, not validation.
 * 4. An id-named local resolved from `env.storage()...get` with no visible
 *    check is reported at low confidence: the target is admin-controlled
 *    rather than user-supplied (weaker signal, GitHub issue #13).
 * 5. No visible boundary at all is reported at low confidence.
 *
 * Not a boundary: `try_*` results (proving the callee is a separate duty),
 * `.unwrap()`/`panic!`/`ok_or` (existence, not validity), a bare rename
 * (`let target = token_id;`), or helper functions — a target resolved by
 * `Self::token_id(&env)` is invisible here. This is single-function,
 * same-body positional reasoning, not interprocedural data flow; those
 * limits are documented rather than guessed at.
 */

/** A sensitive external/token operation worth gating. */
const SENSITIVE_CALL =
  /\b(?:transfer|transfer_from|burn|mint|clawback|set_authorized|set_admin)\s*\(/g;

/** An explicit authorization check inside the function body. */
const AUTH_CHECK = /require_auth(?:_for_args)?\s*\(/;

/** Any id-named value: `token_id`, `contract_id`, `asset_id`, ... */
const ID_MENTION = /\b[A-Za-z_]\w*_id\b/;

/** Explicit validation expressions: assert!/require! or ==/!= comparison. */
const CHECK_EXPR = /\b(?:assert|require)!\s*\(|[!=]==?/;

/** A `let` binding of an id-named local. */
const LET_ID = /\blet\s+([A-Za-z_]\w*_id)\b/;

/** Storage resolution: env.storage()...get(...). */
const STORAGE_GET = /env\s*\.\s*storage\s*\(\)/;

interface CallSite {
  /** Offset of the call within the sanitized body text. */
  offset: number;
}

interface Tier {
  confidence: "medium" | "low";
  message: (fn: string, id?: string) => string;
}

const USER_SUPPLIED_TIER: Tier = {
  confidence: "medium",
  message: (fn, id) =>
    `Function '${fn}' passes user-supplied id '${id}' toward a sensitive external/token operation with no visible validation: the argument name alone is not a boundary. Add an explicit check before the call.`,
};

const STORAGE_TIER: Tier = {
  confidence: "low",
  message: (fn, id) =>
    `Function '${fn}' uses storage-resolved id '${id}' for a sensitive external/token operation with no visible validation. The target is admin-controlled storage rather than user input, but should still be validated where user input can influence it.`,
};

const PLAIN_TIER: Tier = {
  confidence: "low",
  message: (fn) =>
    `Function '${fn}' performs a sensitive external/token operation with no address validation or require_auth boundary. Verify the target contract/address is validated before relying on the call.`,
};

export class UnvalidatedExternalCallPlugin implements Rule, FunctionRule {
  id = "AP-CALL-001";
  name = "Unvalidated External Call";
  description =
    "Detects token-movement or admin-change operations against external token/contract clients where no require_auth or explicitly checked address validation appears before the call";

  scan(code: string): Vulnerability[] {
    return extractRustFunctions(sanitizeKeepLines(code)).flatMap((fn) =>
      this.scanFunction(fn),
    );
  }

  /** The engine passes functions extracted from raw source; sanitize first. */
  scanFunction(fn: ScannedFunction): Vulnerability[] {
    const body = sanitizeKeepLines(fn.bodyInner);
    const callSites = findCallSites(body);

    if (callSites.length === 0 || AUTH_CHECK.test(body)) {
      return [];
    }

    const lines = body.split("\n");
    const checkedIds = collectCheckedIds(lines);
    const storageIds = collectStorageResolvedIds(lines);
    const paramIds = idNamedParameters(fn.body);

    for (const call of callSites) {
      const checkedBefore = checkedIds.find((c) => c.offset < call.offset);
      if (checkedBefore !== undefined) {
        continue;
      }
      const storageBefore = storageIds.find(
        (s) => s.offset < call.offset && s.usesBefore(call, body),
      );
      if (storageBefore !== undefined) {
        return [finding(fn, STORAGE_TIER, storageBefore.name, call.offset)];
      }
      if (paramIds.length > 0) {
        return [finding(fn, USER_SUPPLIED_TIER, paramIds[0], call.offset)];
      }
      return [finding(fn, PLAIN_TIER, undefined, call.offset)];
    }
    return [];
  }
}

function finding(fn: ScannedFunction, tier: Tier, id?: string, callOffset?: number): Vulnerability {
  let location = functionLocation(fn);
  if (callOffset !== undefined) {
    const exprLoc = findExpressionLocation(fn, callOffset);
    if (exprLoc !== null) {
      location = {
        line: exprLoc.line,
        column: exprLoc.column,
        function: fn.name,
      };
    }
  }
  return {
    id: "AP-CALL-001",
    message: tier.message(fn.name, id),
    severity: "high",
    confidence: tier.confidence,
    location,
    remediation:
      "Validate the external contract address and its returned values, and gate the operation with env.require_auth(&...), so only authorized parties can trigger the cross-contract interaction.",
  };
}

/** Offsets of every sensitive call in the sanitized body. */
function findCallSites(body: string): CallSite[] {
  const sites: CallSite[] = [];
  for (const match of body.matchAll(SENSITIVE_CALL)) {
    sites.push({ offset: match.index ?? 0 });
  }
  return sites;
}

/**
 * Ids that are explicitly checked before use: lines carrying both an
 * id mention and an assert!/require! or ==/!= comparison, with the
 * position of the id mention (so a check after the call does not gate it).
 */
function collectCheckedIds(
  lines: string[],
): { name: string; offset: number }[] {
  const checked: { name: string; offset: number }[] = [];
  let offset = 0;
  for (const line of lines) {
    const id = ID_MENTION.exec(line);
    if (id !== null && CHECK_EXPR.test(line)) {
      checked.push({ name: id[0], offset: offset + (id.index ?? 0) });
    }
    offset += line.length + 1;
  }
  return checked;
}

/**
 * Id-named locals resolved from contract storage (`let token_id = ... /
 * env.storage()...get(...)`), including resolutions wrapped over several
 * lines up to the terminating `;`.
 */
function collectStorageResolvedIds(
  lines: string[],
): { name: string; offset: number; usesBefore(call: CallSite, body: string): boolean }[] {
  const resolved: { name: string; offset: number; endOffset: number }[] = [];
  let offset = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const decl = LET_ID.exec(line);
    if (decl) {
      const name = decl[1] ?? "";
      // The resolution may wrap; take text through the line holding the `;`.
      let text = line;
      let end = i;
      while (!text.includes(";") && end + 1 < lines.length && end - i < 6) {
        end++;
        text += `\n${lines[end] ?? ""}`;
      }
      if (STORAGE_GET.test(text) && /\.get\s*\(/.test(text)) {
        resolved.push({
          name,
          offset: offset + (decl.index ?? 0),
          endOffset: offset + text.length,
        });
      }
    }
    offset += line.length + 1;
  }

  return resolved.map((r) => ({
    name: r.name,
    offset: r.offset,
    usesBefore: (call: CallSite, body: string) =>
      // Same-function let-before-use: an id-named local declared from
      // storage before the call, still mentioned at or after the call site
      r.offset < call.offset &&
      // (call arguments follow the call's opening paren).
      new RegExp(`\\b${r.name}\\b`).test(body.slice(r.endOffset, call.offset + 120)),
  }));
}

/** Parameter names ending in `_id`, from the function signature. */
function idNamedParameters(declaration: string): string[] {
  const signature = declaration.slice(0, declaration.indexOf("{"));
  const names: string[] = [];
  for (const match of signature.matchAll(/([A-Za-z_]\w*)\s*:/g)) {
    const name = match[1] ?? "";
    if (name.endsWith("_id")) {
      names.push(name);
    }
  }
  return names;
}

export default new UnvalidatedExternalCallPlugin();
