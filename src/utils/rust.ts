/**
 * Shared text helpers for scanning Rust/Soroban source code.
 * Kept here so every rule strips comments in exactly the same way.
 *
 * This is plain source-text analysis, not a Rust AST analyzer. These helpers
 * exist so rules stay small and agree on how "clean" source is derived.
 */

/**
 * Removes `//` line comments and `/* ... *&#47;` block comments.
 *
 * Rules must compute findings on comment-free code so commented-out
 * examples never trigger them.
 */
export function removeComments(code: string): string {
  return code.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
}

/**
 * Removes `//` line comments and `/* ... *&#47;` block comments while keeping
 * line numbering: stripped text is replaced with spaces (newlines kept).
 *
 * Rules that report per-line locations should use this so the findings
 * point at the line that actually contained the suspicious code.
 */
export function removeCommentsKeepLines(code: string): string {
  return code
    .replace(/\/\/.*$/gm, (match) => " ".repeat(match.length))
    .replace(/\/\*[\s\S]*?\*\//g, (match) =>
      match.replace(/[^\n]/g, " "),
    );
}

import type { ScannedFunction, SourceLocation } from "../types";

/**
 * Blanks out the contents of string/char literals (keeping the quotes and
 * line count) so patterns inside string text, e.g. `"a.unwrap()"`, are not
 * matched. Call it on comment-free code.
 */
export function blankStringContents(code: string): string {
  return code.replace(
    /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g,
    (match) => match.replace(/[^"'\n]/g, " "),
  );
}

/** Both steps above, for rules that scan per line. */
export function sanitizeKeepLines(code: string): string {
  return blankStringContents(removeCommentsKeepLines(code));
}

/**
 * Best available location for a finding anchored to a whole function: the
 * `fn` keyword's line, plus its column when the AST provided one. Columns
 * are never invented for text-fallback extractions.
 */
export function functionLocation(fn: ScannedFunction): SourceLocation {
  return fn.column === undefined
    ? { line: fn.line, function: fn.name }
    : { line: fn.line, column: fn.column, function: fn.name };
}

/**
 * The scanned function whose body contains the 1-based `line`, or null.
 * Declarations cannot nest, so at most one function matches.
 */
function functionAtLine(
  fns: ScannedFunction[],
  line: number,
): ScannedFunction | null {
  for (const fn of fns) {
    if (fn.bodyLine <= line && line <= fn.endLine) {
      return fn;
    }
  }
  return null;
}

/**
 * Best location for a whole-file match on `line`: the line itself, plus the
 * enclosing function's name and `fn`-keyword column when the AST extraction
 * is available. Without it (null), only the line is reported.
 */
export function locateLine(
  functions: ScannedFunction[] | null,
  line: number,
): SourceLocation {
  const fn = functions === null ? null : functionAtLine(functions, line);
  if (fn === null) {
    return { line };
  }
  return fn.column === undefined
    ? { line, function: fn.name }
    : { line, column: fn.column, function: fn.name };
}

/**
 * Extracts top-level functions by brace counting, one nesting level per
 * function. `macro_rules!` blocks are skipped as a unit (brace-based, no
 * macro internals are parsed). Single-line outer attributes on or directly
 * above the declaration line are collected into `attributes`.
 */
export function extractRustFunctions(code: string): ScannedFunction[] {
  const lines = code.split("\n");
  const fns: ScannedFunction[] = [];
  let current: {
    line: number;
    name: string;
    body: string[];
    depth: number;
    attributes: string[];
  } | null = null;

  const count = (line: string, ch: "{" | "}"): number =>
    line.split(ch).length - 1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";

    if (current === null) {
      // Skip macro_rules! bodies entirely.
      if (/macro_rules!/.test(line)) {
        let depth = count(line, "{") - count(line, "}");
        while (depth > 0 && i + 1 < lines.length) {
          i++;
          depth += count(lines[i] ?? "", "{") - count(lines[i] ?? "", "}");
        }
        continue;
      }

      const match = /\bfn\s+([A-Za-z_]\w*)\s*[(<]/.exec(line);
      if (!match) {
        continue;
      }
      current = {
        line: i + 1,
        name: match[1] ?? "<anonymous>",
        body: [line],
        depth: 0,
        attributes: attributesBefore(lines, i, line.slice(0, match.index)),
      };
    } else {
      current.body.push(line);
    }

    if (current === null) {
      continue;
    }
    current.depth += count(line, "{") - count(line, "}");
    if (current.depth <= 0) {
      const body = current.body.join("\n");
      const open = body.indexOf("{");
      fns.push({
        line: current.line,
        endLine: i + 1,
        name: current.name,
        body,
        bodyInner: open >= 0 ? body.slice(open + 1) : "",
        bodyLine: current.line + (open >= 0 ? body.slice(0, open).split("\n").length - 1 : 0),
        attributes: current.attributes,
      });
      current = null;
    }
  }

  return fns;
}

/**
 * Outer attributes of the function declared on `lines[fnIndex]`: those on
 * the declaration line before the `fn` keyword (`prefix`), plus whole lines
 * of attributes directly above it. Blank and comment-only lines are skipped
 * (comments are blank in sanitized input); any other line ends the run, so
 * attributes never leak across items. An attribute spanning several lines
 * is not collected.
 */
function attributesBefore(lines: string[], fnIndex: number, prefix: string): string[] {
  const collected = leadingAttributes(prefix).attributes;
  for (let j = fnIndex - 1; j >= 0; j--) {
    const text = (lines[j] ?? "").trim();
    if (text === "" || text.startsWith("//")) {
      continue;
    }
    const { attributes, rest } = leadingAttributes(text);
    if (attributes.length === 0 || rest.trim() !== "") {
      break;
    }
    collected.unshift(...attributes);
  }
  return collected;
}

/**
 * Outer attributes (`#[...]`; inner `#![...]` excluded) at the start of
 * `text`, nested brackets balanced, plus whatever follows them.
 */
function leadingAttributes(text: string): { attributes: string[]; rest: string } {
  const attributes: string[] = [];
  let i = 0;
  for (;;) {
    while (i < text.length && /\s/.test(text[i] ?? "")) i++;
    if (!text.startsWith("#[", i)) break;
    let depth = 0;
    let end = i + 1;
    for (; end < text.length; end++) {
      if (text[end] === "[") depth++;
      else if (text[end] === "]" && --depth === 0) break;
    }
    if (end >= text.length) break; // continues on the next line
    attributes.push(text.slice(i + 2, end).replace(/\s+/g, " ").trim());
    i = end + 1;
  }
  return { attributes, rest: text.slice(i) };
}

/**
 * Attribute macros that expand to an authorization check placed before the
 * first statement of the function body. The names are those of the
 * OpenZeppelin Stellar contracts library (`stellar_macros`), matched with
 * any path prefix (`#[stellar_macros::only_owner]`):
 *
 * - `only_owner`, `only_admin`: load the stored owner/admin and call
 *   `require_auth()` on it;
 * - `only_role(account, "role")`, `only_any_role(account, [..])`: check
 *   role membership, then call `account.require_auth()`.
 *
 * Deliberately absent: `has_role` / `has_any_role` check role membership
 * WITHOUT calling `require_auth()`, so anyone can pass a role holder's
 * address; pause guards (`when_paused`, `when_not_paused`) are not
 * authorization. Other attribute macros are opaque: their expansion is not
 * visible to source-text analysis.
 */
const AUTH_ATTRIBUTE =
  /^(?:::)?(?:[A-Za-z_]\w*\s*::\s*)*(?:only_owner|only_admin|only_role|only_any_role)\s*(?:\(|$)/;

/**
 * Whether the function carries an attribute macro that authorizes the
 * caller before its body runs (see AUTH_ATTRIBUTE).
 */
export function hasAuthAttribute(fn: ScannedFunction): boolean {
  return fn.attributes?.some((attribute) => AUTH_ATTRIBUTE.test(attribute)) ?? false;
}

/** Finds the 1-based line of the first regex match, or null when absent. */
export function findFirstMatchLine(
  lines: string[],
  pattern: RegExp,
): number | null {
  const index = lines.findIndex((line) => pattern.test(line));
  return index === -1 ? null : index + 1;
}
