import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AuditEngine } from "../src/engine";
import { extractFunctions, parseRust } from "../src/parser/rust";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import MissingRequireAuthPlugin from "../src/plugins/missingRequireAuth";
import UnprotectedUpgradePlugin from "../src/plugins/unprotectedUpgrade";
import UnvalidatedExternalCallPlugin from "../src/plugins/unvalidatedExternalCall";
import { createDefaultRegistry } from "../src/registry";
import type { ScannedFunction } from "../src/types";
import {
  authorizationMacroNames,
  extractRustFunctions,
  hasTtlExtension,
  ttlExtensionMacroNames,
} from "../src/utils/rust";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function scanFunction(plugin: { scan(code: string): unknown[] }, body: string): unknown[] {
  return plugin.scan(`impl Vault {\n${body}\n}`);
}

describe("outer function attributes", () => {
  it("extracts stacked and path-qualified attributes from the AST", () => {
    const code = [
      "#[when_not_paused]",
      "/// documentation does not break the attribute run",
      "#[stellar_macros::only_role(caller, \"manager\")]",
      "pub fn upgrade(e: Env) {}",
      "fn unguarded(e: Env) {}",
    ].join("\n");

    const functions = extractFunctions(parseRust(code)!.tree);
    expect(functions[0]?.attributes).toEqual([
      "when_not_paused",
      'stellar_macros::only_role(caller, "manager")',
    ]);
    expect(functions[1]?.attributes).toEqual([]);
  });

  it("collects single-line attributes in the text fallback without leaking them", () => {
    const code = [
      "#[only_admin]",
      "// comment between the attribute and declaration",
      "fn reset() {}",
      "",
      "fn ordinary() {}",
    ].join("\n");
    const functions = extractRustFunctions(code);

    expect(functions[0]?.attributes).toEqual(["only_admin"]);
    expect(functions[1]?.attributes).toEqual([]);
  });

  it("handles multi-line attributes on the AST path", () => {
    const code = [
      "#[only_role(",
      "    caller,",
      "    \"manager\"",
      ")]",
      "fn upgrade(e: Env) {}",
    ].join("\n");

    const fn = extractFunctions(parseRust(code)!.tree)[0]!;
    expect(fn.attributes?.[0]).toContain("only_role");
  });
});

describe("local macro_rules! authorization boundaries", () => {
  it("finds direct and transitive authorization macros", () => {
    const code = [
      "macro_rules! gate { ($e:expr, $u:expr) => { $e.require_auth($u); }; }",
      "macro_rules! outer { ($e:expr, $u:expr) => { gate!($e, $u); }; }",
      "macro_rules! passive { ($x:expr) => { assert!($x); }; }",
    ].join("\n");

    expect([...authorizationMacroNames(code)].sort()).toEqual(["gate", "outer"]);
  });

  it("ignores authorization text in comments and strings", () => {
    const code = [
      "macro_rules! commented { () => { /* require_auth(&x); */ }; }",
      'macro_rules! stringy { () => { let s = "require_auth(&x)"; }; }',
    ].join("\n");
    expect(authorizationMacroNames(code).size).toBe(0);
  });

  it("respects source order for direct and nested macro gates", () => {
    const guarded = scanFunction(
      MissingRequireAuthPlugin,
      [
        "macro_rules! gate { ($e:expr, $u:expr) => { $e.require_auth($u); }; }",
        "macro_rules! outer { ($e:expr, $u:expr) => { gate!($e, $u); }; }",
        "fn payout(env: Env, to: Address, amount: i128) {",
        "  outer!(&env, &to);",
        "  client.transfer(&to, &amount);",
        "}",
      ].join("\n"),
    );
    const late = scanFunction(
      MissingRequireAuthPlugin,
      [
        "macro_rules! gate { ($e:expr, $u:expr) => { $e.require_auth($u); }; }",
        "fn payout(env: Env, to: Address, amount: i128) {",
        "  client.transfer(&to, &amount);",
        "  gate!(&env, &to);",
        "}",
      ].join("\n"),
    );

    expect(guarded).toHaveLength(0);
    expect(late).toHaveLength(1);
  });

  it("does not mistake an auth-named helper function for a macro", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  authorize(&env, &to);",
      "  client.transfer(&to, &amount);",
      "}",
    ].join("\n");
    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(1);
  });
});

describe("authorization boundaries across rule families", () => {
  it("recognizes attributes and local macros for AP-UPG-001", () => {
    const attribute = [
      "#[only_admin]",
      "fn upgrade(env: Env) { env.storage().instance().set(&KEY, &1); }",
    ].join("\n");
    const macroGuard = [
      "macro_rules! gate { ($e:expr, $a:expr) => { $e.require_auth($a); }; }",
      "fn upgrade(env: Env, admin: Address) {",
      "  gate!(&env, &admin);",
      "  env.storage().instance().set(&KEY, &1);",
      "}",
    ].join("\n");

    expect(UnprotectedUpgradePlugin.scan(attribute)).toHaveLength(0);
    expect(UnprotectedUpgradePlugin.scan(macroGuard)).toHaveLength(0);
  });

  it("recognizes attributes and local macros for AP-CALL-001", () => {
    const attribute = [
      "#[only_role(caller, \"operator\")]",
      "fn pay(env: Env, caller: Address, token: Address, to: Address, amount: i128) {",
      "  token::Client::new(&env, &token).transfer(&caller, &to, &amount);",
      "}",
    ].join("\n");
    const macroGuard = [
      "macro_rules! gate { ($e:expr, $a:expr) => { $e.require_auth($a); }; }",
      "fn pay(env: Env, caller: Address, token: Address, to: Address, amount: i128) {",
      "  gate!(&env, &caller);",
      "  token::Client::new(&env, &token).transfer(&caller, &to, &amount);",
      "}",
    ].join("\n");

    expect(UnvalidatedExternalCallPlugin.scan(attribute)).toHaveLength(0);
    expect(UnvalidatedExternalCallPlugin.scan(macroGuard)).toHaveLength(0);
  });

  it("does not treat role checks or pause guards as authorization", () => {
    const code = [
      "#[has_role(caller, \"operator\")]",
      "#[when_not_paused]",
      "fn pay(env: Env, caller: Address, to: Address, amount: i128) {",
      "  client.transfer(&caller, &to, &amount);",
      "}",
    ].join("\n");
    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(1);
  });
});

describe("TTL extension macros", () => {
  it("recognizes direct and transitive TTL macros", () => {
    const code = [
      "macro_rules! bump { ($s:expr, $k:expr) => { $s.extend_ttl($k, 10, 20); }; }",
      "macro_rules! wrap { ($s:expr, $k:expr) => { bump!($s, $k); }; }",
    ].join("\n");
    const names = ttlExtensionMacroNames(code);

    expect([...names].sort()).toEqual(["bump", "wrap"]);
    expect(hasTtlExtension("wrap!(&storage, &key);", names)).toBe(true);
  });

  it("suppresses AP-STORAGE-001 only when the TTL macro is present", () => {
    const guarded = [
      "macro_rules! bump { ($s:expr, $k:expr) => { $s.extend_ttl($k, 10, 20); }; }",
      "fn touch(env: Env, key: Symbol) {",
      "  let storage = env.storage().persistent();",
      "  bump!(&storage, &key);",
      "}",
    ].join("\n");
    const unguarded = guarded.replace("  bump!(&storage, &key);", "");

    expect(MissingExtendTtlPlugin.scan(guarded)).toHaveLength(0);
    expect(MissingExtendTtlPlugin.scan(unguarded)).toHaveLength(1);
  });
});

describe("macro boundary fixture", () => {
  it("reports only deliberately vulnerable functions", () => {
    const code = fs.readFileSync(
      path.join(ROOT, "contracts", "MacroExpansionBoundaries.rs"),
      "utf-8",
    );
    const findings = new AuditEngine(createDefaultRegistry()).run(code);
    const authFunctions = findings
      .filter((finding) => finding.id === "AP-AUTH-001")
      .map((finding) => finding.location.function)
      .sort();

    expect(authFunctions).toEqual([
      "late_macro_guard",
      "role_check_only",
      "unrelated_macro",
    ]);
    expect(findings.some((finding) => finding.id === "AP-STORAGE-001")).toBe(false);
    expect(
      findings.filter((finding) => finding.id === "AP-UPG-001").map((finding) => finding.location.function),
    ).not.toContain("upgrade");
  });
});
