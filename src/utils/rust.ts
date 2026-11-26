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
 * macro internals are parsed).
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
        attributes: leadingAttributes(lines, i),
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
 * Single-line outer attributes directly above a function. Blank lines and
 * comments are permitted between attributes, as they are in Rust. A
 * multi-line attribute is deliberately not collected by this conservative
 * fallback; the AST path handles it.
 */
function leadingAttributes(lines: string[], functionLine: number): string[] {
  const attributes: string[] = [];
  for (let i = functionLine - 1; i >= 0; i--) {
    const line = (lines[i] ?? "").trim();
    if (line === "" || line.startsWith("//") || line.startsWith("/*")) {
      continue;
    }
    if (line.startsWith("#[") && line.endsWith("]")) {
      attributes.unshift(line.slice(2, -1).replace(/\s+/g, " ").trim());
      continue;
    }
    break;
  }
  return attributes;
}

/** Canonical authorization attribute names whose expansion signs the call. */
const AUTH_ATTRIBUTE = /(?:^|::)(only_owner|only_admin|only_role|only_any_role|require_auth)(?=\s*(?:[\(\],]|$))/i;

export function hasAuthAttribute(fn: ScannedFunction): boolean {
  return (fn.attributes ?? []).some((attribute) => AUTH_ATTRIBUTE.test(attribute));
}

/** An inline authorization function or method call. */
const AUTH_CALL_SOURCE = String.raw`require_auth(?:_for_args)?\s*\(`;

/** A recognized storage TTL extension call. */
const TTL_CALL = /\.extend_ttl\s*\(|extend_ttl_to_threshold\s*\(|get_extended\s*\(/;

const MACRO_CALL = /\b([A-Za-z_]\w*)\s*!\s*[\(\[\{]/g;

interface MacroDefinition {
  name: string;
  body: string;
  start: number;
  end: number;
}

/**
 * Parses local `macro_rules!` definitions well enough to build a call graph.
 * Strings and comments are blanked first; braces are then counted to find the
 * complete definition. This is token-level reasoning, not compiler expansion.
 */
export function extractMacroDefinitions(code: string): MacroDefinition[] {
  const clean = sanitizeKeepLines(code);
  const definitions: MacroDefinition[] = [];
  const header = /macro_rules!\s*([A-Za-z_]\w*)\s*\{/g;
  for (let match = header.exec(clean); match !== null; match = header.exec(clean)) {
    let depth = 1;
    let end = header.lastIndex;
    for (; end < clean.length && depth > 0; end++) {
      if (clean[end] === "{") depth++;
      else if (clean[end] === "}") depth--;
    }
    if (depth !== 0) break;
    definitions.push({
      name: match[1] ?? "",
      body: clean.slice(header.lastIndex, end - 1),
      start: match.index,
      end,
    });
    header.lastIndex = end;
  }
  return definitions;
}

function macroNamesReaching(code: string, direct: RegExp): ReadonlySet<string> {
  const definitions = extractMacroDefinitions(code);
  const reached = new Set(
    definitions.filter((definition) => direct.test(definition.body)).map((definition) => definition.name),
  );

  // Macro wrappers may delegate to another wrapper. Iterate to a fixed point
  // so A! -> B! -> require_auth is treated the same as a direct call.
  let changed = true;
  while (changed) {
    changed = false;
    for (const definition of definitions) {
      if (reached.has(definition.name)) continue;
      for (const call of definition.body.matchAll(MACRO_CALL)) {
        if (reached.has(call[1] ?? "")) {
          reached.add(definition.name);
          changed = true;
          break;
        }
      }
    }
  }
  return reached;
}

/** Local macros whose every recognized body reaches `require_auth[ _for_args]`. */
export function authorizationMacroNames(code: string): ReadonlySet<string> {
  return macroNamesReaching(code, new RegExp(AUTH_CALL_SOURCE));
}

/** Local macros that reach a recognized TTL extension API. */
export function ttlExtensionMacroNames(code: string): ReadonlySet<string> {
  return macroNamesReaching(code, TTL_CALL);
}

function firstMacroInvocation(body: string, names: ReadonlySet<string>): number | null {
  let earliest: number | null = null;
  for (const call of body.matchAll(MACRO_CALL)) {
    if (!names.has(call[1] ?? "")) continue;
    const offset = call.index ?? 0;
    if (earliest === null || offset < earliest) earliest = offset;
  }
  return earliest;
}

/**
 * Earliest authorization boundary in a function body, or null when absent.
 * Authorization attributes expand before the first statement, so they win at
 * offset zero. Inline and local-macro boundaries retain source order.
 */
export function firstAuthorizationOffset(
  fn: ScannedFunction,
  macros: ReadonlySet<string> = new Set(),
): number | null {
  if (hasAuthAttribute(fn)) return 0;
  const body = sanitizeKeepLines(fn.bodyInner);
  const direct = new RegExp(AUTH_CALL_SOURCE).exec(body);
  const macro = firstMacroInvocation(body, macros);
  if (direct === null) return macro;
  if (macro === null) return direct.index;
  return Math.min(direct.index, macro);
}

export function hasAuthorizationBoundary(
  fn: ScannedFunction,
  macros: ReadonlySet<string> = new Set(),
): boolean {
  return firstAuthorizationOffset(fn, macros) !== null;
}

export function hasTtlExtension(
  code: string,
  macros: ReadonlySet<string> = ttlExtensionMacroNames(code),
): boolean {
  const clean = removeComments(code);
  // A definition contains implementation text but cannot extend TTL by itself.
  // Blank definitions while preserving line breaks, then look for a real call.
  let executable = clean;
  for (const definition of extractMacroDefinitions(code)) {
    executable =
      executable.slice(0, definition.start) +
      executable.slice(definition.start, definition.end).replace(/[^\n]/g, " ") +
      executable.slice(definition.end);
  }
  return TTL_CALL.test(executable) || firstMacroInvocation(executable, macros) !== null;
}

/** Finds the 1-based line of the first regex match, or null when absent. */
export function findFirstMatchLine(
  lines: string[],
  pattern: RegExp,
): number | null {
  const index = lines.findIndex((line) => pattern.test(line));
  return index === -1 ? null : index + 1;
}
