import { createRequire } from "module";
import type { ScannedFunction } from "../types";
import { sanitizeKeepLines } from "../utils/rust.js";

/**
 * Isolated Tree-sitter Rust parser (AP-005).
 *
 * tree-sitter is a native module and can fail to load on machines without a
 * prebuilt binary. The failure is contained here: `parseRust` returns null
 * instead of throwing, so callers can keep using their source-text analysis.
 * Nothing outside this module imports tree-sitter.
 *
 * This is structural parsing only: it yields syntax trees and syntax-error
 * detection, not Rust semantics or types.
 */

type ParserCtor = typeof import("tree-sitter");
type ParserInstance = InstanceType<ParserCtor>;

/** A parsed Rust source tree plus a syntax-error flag. */
export interface RustParseResult {
  tree: import("tree-sitter").Tree;
  /** True when the source has syntax errors; the tree is still usable. */
  hasError: boolean;
}

const nodeRequire = createRequire(import.meta.url);

let cachedParser: ParserInstance | null | undefined;

function getParser(): ParserInstance | null {
  if (cachedParser !== undefined) {
    return cachedParser;
  }
  try {
    const Parser = nodeRequire("tree-sitter") as ParserCtor;
    const Rust =
      nodeRequire("tree-sitter-rust") as Parameters<ParserInstance["setLanguage"]>[0];
    const parser = new Parser();
    parser.setLanguage(Rust);
    cachedParser = parser;
  } catch {
    cachedParser = null;
  }
  return cachedParser;
}

/**
 * Parses Rust source with tree-sitter. Returns null when the parser cannot
 * be loaded. Parsing never throws: tree-sitter recovers from syntax errors
 * and still produces a tree, with `hasError` set.
 */
export function parseRust(code: string): RustParseResult | null {
  const parser = getParser();
  if (parser === null) {
    return null;
  }

  const tree = parser.parse(code);
  return { tree, hasError: tree.rootNode.hasError };
}

/**
 * Extracts function declarations from a parsed tree: name, boundaries, and
 * body range. Declared function bodies are not descended into (nested
 * `function_item`s cannot occur inside a body), so each declaration is
 * visited exactly once.
 */
export function extractFunctions(tree: import("tree-sitter").Tree): ScannedFunction[] {
  return collectFunctions(tree.rootNode, []);
}

/**
 * Convenience for rules: parse `code` and extract functions in one step.
 * Returns null when the parser is unavailable or the tree has syntax
 * errors, so callers can fall back to their source-text analysis.
 */
export function extractRustFunctionsAst(code: string): ScannedFunction[] | null {
  const parsed = parseRust(code);
  if (parsed === null || parsed.hasError) {
    return null;
  }
  return extractFunctions(parsed.tree);
}

function collectFunctions(
  node: import("tree-sitter").SyntaxNode,
  out: ScannedFunction[],
): ScannedFunction[] {
  for (const child of node.children) {
    if (child.type === "function_item") {
      const fn = toAstFunction(child);
      if (fn) out.push(fn);
      continue; // declarations cannot nest inside declared bodies
    }
    collectFunctions(child, out);
  }
  return out;
}

function toAstFunction(node: import("tree-sitter").SyntaxNode): ScannedFunction | null {
  const nameNode = node.childForFieldName("name");
  const bodyNode = node.childForFieldName("body");
  if (nameNode === null || bodyNode === null) {
    return null;
  }

  // Anchor the reported line to the `fn` keyword: attributes sit outside the
  // node, but `pub`/`const` share its first line, so the node start would
  // usually agree — the token is exact in every case.
  const fnToken = node.children.find((child) => child.type === "fn");
  const body = node.text;
  const open = body.indexOf("{");
  // 1-based line of the body's opening brace, derived from the same text so
  // it stays consistent with `body`.
  const bodyLine =
    open >= 0
      ? (fnToken ?? node).startPosition.row + 1 + body.slice(0, open).split("\n").length - 1
      : node.endPosition.row + 1;
  return {
    name: nameNode.text,
    line: (fnToken ?? node).startPosition.row + 1,
    // Tree-sitter columns are 0-based character offsets; report 1-based.
    column: (fnToken ?? node).startPosition.column + 1,
    endLine: node.endPosition.row + 1,
    body,
    bodyInner: open >= 0 ? body.slice(open + 1) : "",
    bodyLine,
    bodyColumn: bodyNode.startPosition.column + 1,
  };
}

export interface FindExpressionOptions {
  /**
   * Whether to blank out comments and string literals with equivalent whitespace
   * before matching, so that commented-out code or string contents do not produce
   * false or ambiguous matches. Defaults to true.
   */
  sanitize?: boolean;
}

/**
 * Maps an expression, needle pattern, or character offset inside a function's
 * body (`fn.bodyInner`) to a 1-based source location `{ line, column }`.
 *
 * Requirements & design rules:
 * - If `fn.bodyColumn === undefined` (text-fallback extraction without AST coordinates),
 *   always returns `null` to avoid inventing pseudo-precise columns.
 * - If `target` is a string or RegExp, comments and strings are sanitized by default
 *   so that comments/string literals do not interfere.
 * - If `target` matches multiple times (ambiguous) or zero times, returns `null`
 *   to avoid misattributing the finding to the wrong expression.
 * - If `target` is a numeric offset, directly maps that offset in `fn.bodyInner`
 *   to 1-based `{ line, column }`.
 */
export function findExpressionLocation(
  fn: ScannedFunction,
  target: string | RegExp | number,
  options?: FindExpressionOptions,
): { line: number; column: number } | null {
  if (fn.bodyColumn === undefined) {
    return null;
  }

  let offset: number;

  if (typeof target === "number") {
    if (target < 0 || target > fn.bodyInner.length || !Number.isFinite(target)) {
      return null;
    }
    offset = Math.floor(target);
  } else {
    const text = options?.sanitize === false ? fn.bodyInner : sanitizeKeepLines(fn.bodyInner);

    if (typeof target === "string") {
      if (target.length === 0) {
        return null;
      }
      const first = text.indexOf(target);
      if (first === -1) {
        return null;
      }
      const second = text.indexOf(target, first + 1);
      if (second !== -1) {
        return null; // Ambiguous: multiple matches
      }
      offset = first;
    } else {
      const flags = target.flags.includes("g") ? target.flags : `${target.flags}g`;
      const regex = new RegExp(target.source, flags);
      const matches = [...text.matchAll(regex)];
      if (matches.length !== 1 || matches[0].index === undefined) {
        return null; // Zero or multiple matches
      }
      offset = matches[0].index;
    }
  }

  const prefix = fn.bodyInner.slice(0, offset);
  const lines = prefix.split("\n");

  if (lines.length === 1) {
    return {
      line: fn.bodyLine,
      column: fn.bodyColumn + 1 + offset,
    };
  }

  return {
    line: fn.bodyLine + lines.length - 1,
    column: lines[lines.length - 1]!.length + 1,
  };
}
