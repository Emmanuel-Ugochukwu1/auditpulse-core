import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { parseRust, extractFunctions } from "../src/parser/rust";
import { extractRustFunctions, sanitizeKeepLines } from "../src/utils/rust";
import MissingRequireAuthPlugin from "../src/plugins/missingRequireAuth";
import UnprotectedUpgradePlugin from "../src/plugins/unprotectedUpgrade";
import UnvalidatedExternalCallPlugin from "../src/plugins/unvalidatedExternalCall";
import type { Rule, Vulnerability } from "../src/types";

/**
 * Authorization injected by attribute macros.
 *
 * Soroban contracts built on the OpenZeppelin Stellar library gate
 * entrypoints with procedural attribute macros instead of an inline
 * require_auth. The macro expands to the check before the first statement
 * of the body, so the source text of the body never contains it:
 *
 *   #[only_owner]                  -> owner.require_auth()
 *   #[only_admin]                  -> admin.require_auth()
 *   #[only_role(acct, "role")]     -> role check, then acct.require_auth()
 *   #[only_any_role(acct, [..])]   -> role check, then acct.require_auth()
 *   #[has_role(acct, "role")]      -> role check ONLY (no require_auth)
 *   #[when_not_paused]             -> pause guard, not authorization
 *
 * Expected behavior: the four authorizing macros gate the function for
 * AP-AUTH-001, AP-UPG-001 and AP-CALL-001; has_role/has_any_role and pause
 * guards do not; an attribute never leaks onto a neighbouring function; the
 * AST path and the source-text fallback agree.
 */

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function engineRun(code: string): Vulnerability[] {
  return new AuditEngine(createDefaultRegistry()).run(code);
}

/** "RULE function" labels, sorted, optionally for one rule only. */
function labels(findings: Vulnerability[], ruleId?: string): string[] {
  return findings
    .filter((f) => ruleId === undefined || f.id === ruleId)
    .map((f) => `${f.id} ${f.location.function ?? "?"}`)
    .sort();
}

/** Runs a rule through the engine (AST) and through its own text fallback. */
function bothPaths(rule: Rule, code: string): { ast: string[]; fallback: string[] } {
  expect(parseRust(code)!.hasError).toBe(false);
  return {
    ast: labels(engineRun(code), rule.id),
    fallback: labels(rule.scan(code), rule.id),
  };
}

const AUTHORIZING = [
  "#[only_owner]",
  "#[only_admin]",
  '#[only_role(caller, "treasurer")]',
  '#[only_any_role(caller, ["treasurer", "operator"])]',
  "#[stellar_macros::only_owner]",
];

const NOT_AUTHORIZING = [
  '#[has_role(caller, "treasurer")]',
  '#[has_any_role(caller, ["treasurer", "operator"])]',
  "#[when_not_paused]",
];

/** A storage write (AP-AUTH-001-sensitive) under the given attribute line. */
function storageWriter(attribute: string): string {
  return [
    "#[contractimpl]",
    "impl Vault {",
    `    ${attribute}`,
    "    pub fn set_limit(e: &Env, limit: u32, caller: Address) {",
    "        e.storage().instance().set(&DataKey::Limit, &limit);",
    "    }",
    "}",
  ].join("\n");
}

/** OpenZeppelin's upgradeable example shape (AP-UPG-001-sensitive). */
function upgrader(attribute: string): string {
  return [
    "#[contractimpl]",
    "impl Upgradeable for Vault {",
    `    ${attribute}`,
    "    fn upgrade(e: &Env, new_wasm_hash: BytesN<32>, caller: Address) {",
    "        upgradeable::upgrade(e, &new_wasm_hash);",
    "    }",
    "}",
  ].join("\n");
}

/** OpenZeppelin's SAC admin wrapper shape (AP-CALL-001-sensitive). */
function clawback(attribute: string): string {
  return [
    "#[contractimpl]",
    "impl Vault {",
    `    ${attribute}`,
    "    pub fn clawback(e: Env, sac: Address, from: Address, amount: i128, caller: Address) {",
    "        let client = token::StellarAssetClient::new(&e, &sac);",
    "        client.clawback(&from, &amount);",
    "    }",
    "}",
  ].join("\n");
}

describe("attribute extraction", () => {
  const code = [
    "#[contractimpl]",
    "impl Vault {",
    "    /// Doc comments may sit between attributes.",
    "    #[only_owner]",
    "    // so may plain comments",
    '    #[stellar_macros::only_role(caller, "minter")]',
    "    pub fn a(e: &Env, caller: Address) {}",
    "",
    "    #[only_admin] pub fn b(e: &Env) {}",
    "",
    "    pub fn c(e: &Env) {}",
    "",
    "    #[only_any_role(",
    "        caller,",
    '        ["minter", "burner"]',
    "    )]",
    "    pub fn d(e: &Env, caller: Address) {}",
    "}",
    "",
    "mod inner {",
    "    #![allow(dead_code)]",
    "    fn e() {}",
    "}",
  ].join("\n");

  it("AST: collects outer attributes in order, skipping comments, never leaking", () => {
    const fns = extractFunctions(parseRust(code)!.tree);
    const byName = Object.fromEntries(fns.map((fn) => [fn.name, fn.attributes]));

    expect(byName).toEqual({
      a: ["only_owner", 'stellar_macros::only_role(caller, "minter")'],
      b: ["only_admin"],
      c: [],
      d: ['only_any_role( caller, ["minter", "burner"] )'],
      // An inner attribute belongs to the module, not the function.
      e: [],
    });
    // The impl's own attribute is not attributed to any of its methods.
    expect(fns.some((fn) => fn.attributes?.includes("contractimpl"))).toBe(false);
  });

  it("fallback: collects single-line attributes; a multi-line one is not collected", () => {
    // Sanitized input blanks string contents, so compare attribute paths.
    const fns = extractRustFunctions(sanitizeKeepLines(code));
    const byName = Object.fromEntries(
      fns.map((fn) => [fn.name, fn.attributes?.map((a) => a.split("(")[0])]),
    );

    expect(byName.a).toEqual(["only_owner", "stellar_macros::only_role"]);
    expect(byName.b).toEqual(["only_admin"]);
    expect(byName.c).toEqual([]);
    // Conservative: the attribute is missed, so findings are kept, not hidden.
    expect(byName.d).toEqual([]);
    expect(byName.e).toEqual([]);
  });
});

describe("AP-AUTH-001 with attribute macros", () => {
  it("still reports the storage writer when it has no attribute (control)", () => {
    const { ast, fallback } = bothPaths(MissingRequireAuthPlugin, storageWriter(""));

    expect(ast).toEqual(["AP-AUTH-001 set_limit"]);
    expect(fallback).toEqual(ast);
  });

  it.each(AUTHORIZING)("%s gates the storage write", (attribute) => {
    const { ast, fallback } = bothPaths(MissingRequireAuthPlugin, storageWriter(attribute));

    expect(ast).toEqual([]);
    expect(fallback).toEqual([]);
  });

  it.each(NOT_AUTHORIZING)("%s does not authorize the caller", (attribute) => {
    const { ast, fallback } = bothPaths(MissingRequireAuthPlugin, storageWriter(attribute));

    expect(ast).toEqual(["AP-AUTH-001 set_limit"]);
    expect(fallback).toEqual(ast);
  });

  it("#[has_role] with require_auth in the body (the library's documented pattern) is gated", () => {
    const code = [
      "impl Vault {",
      '    #[has_role(caller, "treasurer")]',
      "    pub fn set_limit(e: &Env, limit: u32, caller: Address) {",
      "        caller.require_auth();",
      "        e.storage().instance().set(&DataKey::Limit, &limit);",
      "    }",
      "}",
    ].join("\n");

    expect(bothPaths(MissingRequireAuthPlugin, code)).toEqual({ ast: [], fallback: [] });
  });

  it("does not carry an attribute over to the next function", () => {
    const code = [
      "impl Vault {",
      "    #[only_owner]",
      "    pub fn set_fee(e: &Env, fee: u32) {",
      "        e.storage().instance().set(&DataKey::Fee, &fee);",
      "    }",
      "",
      "    pub fn set_limit(e: &Env, limit: u32) {",
      "        e.storage().instance().set(&DataKey::Limit, &limit);",
      "    }",
      "}",
    ].join("\n");
    const { ast, fallback } = bothPaths(MissingRequireAuthPlugin, code);

    expect(ast).toEqual(["AP-AUTH-001 set_limit"]);
    expect(fallback).toEqual(ast);
  });

  it("an attribute mentioned only in a comment does not gate", () => {
    const code = storageWriter("/// Should be #[only_owner], but is not.");
    const { ast, fallback } = bothPaths(MissingRequireAuthPlugin, code);

    expect(ast).toEqual(["AP-AUTH-001 set_limit"]);
    expect(fallback).toEqual(ast);
  });
});

describe("AP-UPG-001 with attribute macros", () => {
  it("still reports an upgrade with no attribute (control)", () => {
    const { ast, fallback } = bothPaths(UnprotectedUpgradePlugin, upgrader(""));

    expect(ast).toEqual(["AP-UPG-001 upgrade"]);
    expect(fallback).toEqual(ast);
  });

  it.each(AUTHORIZING)("%s protects the upgrade", (attribute) => {
    expect(bothPaths(UnprotectedUpgradePlugin, upgrader(attribute))).toEqual({
      ast: [],
      fallback: [],
    });
  });

  it.each(NOT_AUTHORIZING)("%s leaves the upgrade unprotected", (attribute) => {
    const { ast, fallback } = bothPaths(UnprotectedUpgradePlugin, upgrader(attribute));

    expect(ast).toEqual(["AP-UPG-001 upgrade"]);
    expect(fallback).toEqual(ast);
  });
});

describe("AP-CALL-001 with attribute macros", () => {
  it("still reports the clawback with no attribute (control)", () => {
    const { ast, fallback } = bothPaths(UnvalidatedExternalCallPlugin, clawback(""));

    expect(ast).toEqual(["AP-CALL-001 clawback"]);
    expect(fallback).toEqual(ast);
  });

  it.each(AUTHORIZING)("%s is an authorization boundary for the call", (attribute) => {
    expect(bothPaths(UnvalidatedExternalCallPlugin, clawback(attribute))).toEqual({
      ast: [],
      fallback: [],
    });
  });

  it.each(NOT_AUTHORIZING)("%s is not a boundary for the call", (attribute) => {
    const { ast, fallback } = bothPaths(UnvalidatedExternalCallPlugin, clawback(attribute));

    expect(ast).toEqual(["AP-CALL-001 clawback"]);
    expect(fallback).toEqual(ast);
  });
});

describe("contracts/AccessControlledTreasury.rs", () => {
  const code = fs.readFileSync(
    path.join(ROOT, "contracts", "AccessControlledTreasury.rs"),
    "utf-8",
  );

  it("parses without syntax errors, so the AST path is exercised", () => {
    expect(parseRust(code)!.hasError).toBe(false);
  });

  it("reports only the two functions without an authorizing macro", () => {
    expect(labels(engineRun(code))).toEqual([
      "AP-AUTH-001 pay_unchecked",
      "AP-AUTH-001 set_treasury",
      "AP-CALL-001 pay_unchecked",
      "AP-UPG-001 set_treasury",
    ]);
  });

  it("the source-text fallback reaches the same verdicts", () => {
    const fallback = [
      MissingRequireAuthPlugin,
      UnprotectedUpgradePlugin,
      UnvalidatedExternalCallPlugin,
    ].flatMap((rule) => labels(rule.scan(code)));

    expect(fallback.sort()).toEqual(
      labels(engineRun(code)).filter((label) => /^AP-(AUTH|UPG|CALL)-/.test(label)),
    );
  });
});
