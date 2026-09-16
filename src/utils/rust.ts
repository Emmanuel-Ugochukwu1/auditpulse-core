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

export interface RustFunction {
  /** 1-based line number of the `fn` keyword line. */
  line: number;
  /** Function name. */
  name: string;
  /** Full source of the function, from the `fn` line through the closing brace. */
  body: string;
  /** Text after the opening brace of the body, closing brace included. */
  bodyInner: string;
  /**
   * Detection-only view with bodies of locally-defined `macro_rules!` macros
   * appended when the function invokes them. The original body remains the
   * authority for source locations.
   */
  analysisBody: string;
  /** Detection-only inner body; see analysisBody. */
  analysisBodyInner: string;
}

interface LocalMacroDefinition {
  name: string;
  body: string;
}

function extractLocalMacroDefinitions(code: string): LocalMacroDefinition[] {
  const lines = code.split("\n");
  const definitions: LocalMacroDefinition[] = [];
  const count = (line: string, ch: "{" | "}"): number =>
    line.split(ch).length - 1;

  for (let i = 0; i < lines.length; i++) {
    const start = lines[i] ?? "";
    const match = /\bmacro_rules!\s+([A-Za-z_]\w*)\s*\{/.exec(start);
    if (!match) continue;

    const body = [start];
    let depth = count(start, "{") - count(start, "}");
    let j = i;
    while (depth > 0 && j + 1 < lines.length) {
      j++;
      const line = lines[j] ?? "";
      body.push(line);
      depth += count(line, "{") - count(line, "}");
    }

    definitions.push({ name: match[1] ?? "", body: body.join("\n") });
    i = j;
  }
  return definitions;
}

function expandInvokedLocalMacros(
  body: string,
  definitions: LocalMacroDefinition[],
): string {
  const appended: string[] = [];
  let searchable = body;
  const seen = new Set<string>();

  // Bounded fixed point: enough for local macro -> local macro chains without
  // pretending to be a full Rust macro expander.
  for (let round = 0; round < 4; round++) {
    let changed = false;
    for (const definition of definitions) {
      if (!definition.name || seen.has(definition.name)) continue;
      const escaped = definition.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const invocation = new RegExp(`\\b${escaped}\\s*!\\s*[({[]`);
      if (!invocation.test(searchable)) continue;

      seen.add(definition.name);
      appended.push(definition.body);
      searchable += `\n${definition.body}`;
      changed = true;
    }
    if (!changed) break;
  }

  return appended.length === 0 ? body : `${body}\n${appended.join("\n")}`;
}

/**
 * Extracts top-level functions by brace counting, one nesting level per
 * function. `macro_rules!` blocks are skipped as a unit (brace-based, no
 * macro internals are parsed).
 */
export function extractRustFunctions(code: string): RustFunction[] {
  const lines = code.split("\n");
  const fns: RustFunction[] = [];
  const localMacros = extractLocalMacroDefinitions(code);
  let current: { line: number; name: string; body: string[]; depth: number } | null =
    null;

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
      const bodyInner = open >= 0 ? body.slice(open + 1) : "";
      const analysisBody = expandInvokedLocalMacros(body, localMacros);
      const analysisOpen = analysisBody.indexOf("{");
      fns.push({
        line: current.line,
        name: current.name,
        body,
        bodyInner,
        analysisBody,
        analysisBodyInner:
          analysisOpen >= 0 ? analysisBody.slice(analysisOpen + 1) : "",
      });
      current = null;
    }
  }

  return fns;
}

/** Finds the 1-based line of the first regex match, or null when absent. */
export function findFirstMatchLine(
  lines: string[],
  pattern: RegExp,
): number | null {
  const index = lines.findIndex((line) => pattern.test(line));
  return index === -1 ? null : index + 1;
}
