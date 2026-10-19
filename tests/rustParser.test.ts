import { describe, it, expect } from "vitest";
import { parseRust, extractFunctions, findExpressionLocation } from "../src/parser/rust";
import type { ScannedFunction } from "../src/types";

describe("parseRust", () => {
  it("parses valid Rust without syntax errors", () => {
    const result = parseRust("fn main() { let x = 1; }");

    expect(result).not.toBeNull();
    expect(result!.hasError).toBe(false);
    expect(result!.tree.rootNode.type).toBe("source_file");
  });

  it("flags syntax errors on malformed source", () => {
    const result = parseRust("fn broken( {");

    expect(result).not.toBeNull();
    expect(result!.hasError).toBe(true);
  });

  it("detects a missing closing brace as an error", () => {
    const result = parseRust("fn f() {\n  let x = 1;\n");

    expect(result!.hasError).toBe(true);
  });

  it("treats empty and whitespace-only input as error-free", () => {
    expect(parseRust("")!.hasError).toBe(false);
    expect(parseRust("\n\n  \n")!.hasError).toBe(false);
  });

  it("caches the parser across calls without leaking state", () => {
    const first = parseRust("fn a() {}");
    const second = parseRust("fn b() {}");

    expect(first!.hasError).toBe(false);
    expect(second!.hasError).toBe(false);
  });
});

describe("extractFunctions", () => {
  it("extracts a normal function with correct boundaries", () => {
    const code = "fn add(a: i128, b: i128) -> i128 {\n  a + b\n}\n";
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns).toHaveLength(1);
    expect(fns[0]?.name).toBe("add");
    expect(fns[0]?.line).toBe(1);
    expect(fns[0]?.endLine).toBe(3);
    expect(fns[0]?.body.startsWith("fn add")).toBe(true);
    expect(fns[0]?.bodyInner).toContain("a + b");
  });

  it("handles nested braces inside the body", () => {
    const code = [
      "fn pick(x: bool, a: i128, b: i128) -> i128 {",
      "  if x {",
      "    if a > b { a } else { b }",
      "  } else {",
      "    0",
      "  }",
      "}",
    ].join("\n");
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns).toHaveLength(1);
    expect(fns[0]?.name).toBe("pick");
    expect(fns[0]?.endLine).toBe(7);
    expect(fns[0]?.bodyInner).toContain("else");
  });

  it("does not let comments shift function boundaries", () => {
    const code = [
      "// a leading comment { with a brace",
      "fn f() { /* inline } comment */",
      "  1",
      "}",
      "// trailing } comment",
      "fn g() {}",
    ].join("\n");
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns.map((fn) => fn.name)).toEqual(["f", "g"]);
    expect(fns[0]?.line).toBe(2);
    expect(fns[0]?.endLine).toBe(4);
    expect(fns[1]?.line).toBe(6);
  });

  it("does not let braces in strings end a function body", () => {
    const code = [
      "fn message() -> &'static str {",
      "  \"} { not a boundary \"",
      "}",
      "fn after() {}",
    ].join("\n");
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns.map((fn) => fn.name)).toEqual(["message", "after"]);
    expect(fns[0]?.endLine).toBe(3);
    expect(fns[0]?.bodyInner).toContain("not a boundary");
  });

  it("extracts multiple top-level functions in order", () => {
    const code = "fn a() {}\nfn b() {}\nfn c() {}\n";
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns.map((fn) => fn.name)).toEqual(["a", "b", "c"]);
    expect(fns.map((fn) => fn.line)).toEqual([1, 2, 3]);
  });

  it("extracts functions declared inside impl blocks", () => {
    const code = [
      "impl Vault {",
      "  pub fn deposit(env: Env) {",
      "    env.require_auth(&user);",
      "  }",
      "",
      "  pub fn withdraw(env: Env) {",
      "    client.transfer(&to, &amount);",
      "  }",
      "}",
    ].join("\n");
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns.map((fn) => fn.name)).toEqual(["deposit", "withdraw"]);
    expect(fns[0]?.line).toBe(2);
    expect(fns[1]?.endLine).toBe(8);
    expect(fns.every((fn) => fn.body.startsWith("pub fn"))).toBe(true);
  });

  it("skips bodyless trait signatures and is stable for empty source", () => {
    const code = "trait Pay {\n  fn price(&self) -> i128;\n}\n";
    expect(extractFunctions(parseRust(code)!.tree)).toEqual([]);
    expect(extractFunctions(parseRust("")!.tree)).toEqual([]);
  });

  it("still extracts functions from error-recovered trees", () => {
    const code = "fn ok() {}\nfn broken( {\nfn also_ok() {}\n";
    const result = parseRust(code)!;

    expect(result.hasError).toBe(true);
    const names = extractFunctions(result.tree).map((fn) => fn.name);
    expect(names).toContain("ok");
    expect(names).toContain("also_ok");
  });

  it("reports exact fn-keyword and body-brace positions", () => {
    const code = [
      "impl Vault {", // 1
      "  pub fn deposit(env: Env) {", // 2
      "    env.require_auth(&user);", // 3
      "  }", // 4
      "", // 5
      "fn helper(x: i128) -> i128 { x + 1 }", // 6
      "}", // 7
    ].join("\n");
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns).toHaveLength(2);
    const [deposit, helper] = fns as [
      { name: string; line: number; column: number; bodyLine: number; bodyColumn: number; endLine: number },
      typeof fns[0],
    ];
    expect(deposit.name).toBe("deposit");
    expect(deposit.line).toBe(2);
    expect(deposit.column).toBe(7); // `fn` after "  pub "
    expect(deposit.bodyLine).toBe(2);
    expect(deposit.bodyColumn).toBe(28); // `{` ends the line
    expect(deposit.endLine).toBe(4);

    expect(helper.name).toBe("helper");
    expect(helper.line).toBe(6);
    expect(helper.column).toBe(1);
    expect(helper.bodyLine).toBe(6);
    expect(helper.bodyColumn).toBe(28);
    expect(helper.endLine).toBe(6);
  });

  it("is unaffected by comments and strings when placing columns", () => {
    const code = [
      "// fn phantom() { }", // 1
      "fn real() {", // 2
      "  // } brace in comment", // 3
      "  let s = \"} {\";", // 4
      "}", // 5
    ].join("\n");
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns.map((fn) => fn.name)).toEqual(["real"]);
    expect(fns[0]?.line).toBe(2);
    expect(fns[0]?.column).toBe(1);
    expect(fns[0]?.bodyLine).toBe(2);
    expect(fns[0]?.bodyColumn).toBe(11);
    expect(fns[0]?.endLine).toBe(5);
  });

  it("keeps multi-line signatures anchored to the fn keyword", () => {
    const code = [
      "fn multi(", // 1
      "  a: i128,", // 2
      "  b: i128,", // 3
      ") -> i128 {", // 4
      "  a + b", // 5
      "}", // 6
    ].join("\n");
    const fns = extractFunctions(parseRust(code)!.tree);

    expect(fns).toHaveLength(1);
    const fn = fns[0]!;
    expect(fn.name).toBe("multi");
    expect(fn.line).toBe(1);
    expect(fn.column).toBe(1);
    expect(fn.bodyLine).toBe(4); // the line holding the opening brace
    expect(fn.endLine).toBe(6);
  });
});

describe("findExpressionLocation", () => {
  it("locates an expression on the same line as the opening brace", () => {
    const code = "fn helper(x: i128) -> i128 { x + 1 }";
    const fn = extractFunctions(parseRust(code)!.tree)[0]!;

    const loc = findExpressionLocation(fn, "x + 1");
    expect(loc).toEqual({ line: 1, column: 30 });
  });

  it("locates an expression across subsequent lines in multi-line bodies", () => {
    const code = [
      "fn transfer_funds(env: Env) {", // 1
      "  let target = 42;",            // 2
      "  client.transfer(&target);",    // 3
      "}",                             // 4
    ].join("\n");
    const fn = extractFunctions(parseRust(code)!.tree)[0]!;

    const loc = findExpressionLocation(fn, "client.transfer");
    expect(loc).toEqual({ line: 3, column: 3 });
  });

  it("locates expressions using RegExp patterns", () => {
    const code = [
      "fn work() {",
      "  let amount = 100;",
      "  let balance = amount * 2;",
      "}",
    ].join("\n");
    const fn = extractFunctions(parseRust(code)!.tree)[0]!;

    const loc = findExpressionLocation(fn, /amount\s*\*\s*2/);
    expect(loc).toEqual({ line: 3, column: 17 });
  });

  it("locates by explicit numeric offset within fn.bodyInner", () => {
    const code = "fn one_line() { 12345 }";
    const fn = extractFunctions(parseRust(code)!.tree)[0]!;

    // " 12345 }" -> offset 1 is "1"
    const loc = findExpressionLocation(fn, 1);
    expect(loc).toEqual({ line: 1, column: 17 });
  });

  it("ignores occurrences inside comments and strings by default", () => {
    const code = [
      "fn guarded() {",
      "  // client.transfer(&comment);",
      "  let s = \"client.transfer(&string)\";",
      "  client.transfer(&real);",
      "}",
    ].join("\n");
    const fn = extractFunctions(parseRust(code)!.tree)[0]!;

    // Because comments and strings are blanked out with equivalent whitespace,
    // the only matching occurrence is on line 4, so it is unambiguous.
    const loc = findExpressionLocation(fn, "client.transfer");
    expect(loc).toEqual({ line: 4, column: 3 });
  });

  it("returns null on ambiguous multiple matches", () => {
    const code = [
      "fn double_call() {",
      "  client.transfer(&first);",
      "  client.transfer(&second);",
      "}",
    ].join("\n");
    const fn = extractFunctions(parseRust(code)!.tree)[0]!;

    expect(findExpressionLocation(fn, "client.transfer")).toBeNull();
  });

  it("returns null when expression is not found or empty", () => {
    const code = "fn empty() { let a = 1; }";
    const fn = extractFunctions(parseRust(code)!.tree)[0]!;

    expect(findExpressionLocation(fn, "nonexistent")).toBeNull();
    expect(findExpressionLocation(fn, "")).toBeNull();
  });

  it("returns null when fn.bodyColumn is undefined (text-fallback extraction)", () => {
    const fn: ScannedFunction = {
      name: "fallback_fn",
      line: 1,
      endLine: 3,
      body: "fn fallback_fn() {\n  call();\n}",
      bodyInner: "\n  call();\n}",
      bodyLine: 1,
      // bodyColumn is intentionally omitted
    };

    expect(findExpressionLocation(fn, "call()")).toBeNull();
    expect(findExpressionLocation(fn, 4)).toBeNull();
  });

  it("returns null for negative, infinite, or out-of-bounds numeric offsets", () => {
    const code = "fn small() { 1 }";
    const fn = extractFunctions(parseRust(code)!.tree)[0]!;

    expect(findExpressionLocation(fn, -1)).toBeNull();
    expect(findExpressionLocation(fn, 9999)).toBeNull();
    expect(findExpressionLocation(fn, Number.NaN)).toBeNull();
    expect(findExpressionLocation(fn, Number.POSITIVE_INFINITY)).toBeNull();
  });
});
