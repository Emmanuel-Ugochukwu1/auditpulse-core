import { describe, it, expect } from "vitest";
import MissingRequireAuthPlugin from "../src/plugins/missingRequireAuth";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

/**
 * Structural auth analysis for AP-AUTH-001 (AP-007).
 *
 * Intended behavior, defined before implementation:
 * - The function body from the AST is checked operation by operation.
 * - A sensitive operation is gated when a require_auth (or
 *   require_auth_for_args) call precedes it in the same function body.
 * - A require_auth that appears only AFTER the sensitive operation does not
 *   gate it: the finding survives (ordering matters).
 * - Everything else (which operations count as sensitive, severities,
 *   messages, rule id) stays exactly as before.
 */

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("AP-AUTH-001 authorization ordering", () => {
  it("reports a sensitive operation that precedes require_auth", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  let client = token::Client::new(&env, &token);",
      "  client.transfer(&to, &amount);",
      "  env.require_auth(&to);",
      "}",
    ].join("\n");

    const findings = MissingRequireAuthPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("payout");
  });

  it("stays silent when require_auth precedes the sensitive operation", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  env.require_auth(&to);",
      "  let client = token::Client::new(&env, &token);",
      "  client.transfer(&to, &amount);",
      "}",
    ].join("\n");

    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(0);
  });

  it("require_auth_for_args before the operation still gates it", () => {
    const code = [
      "fn swap(env: Env, args: Vec<Val>) {",
      "  env.require_auth_for_args(&user, &args);",
      "  client.transfer(&to, &amount);",
      "}",
    ].join("\n");

    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(0);
  });

  it("judges each function independently", () => {
    const code = [
      "fn gated_first(env: Env, to: Address, amount: i128) {",
      "  env.require_auth(&to);",
      "  client.transfer(&to, &amount);",
      "}",
      "",
      "fn gated_last(env: Env, to: Address, amount: i128) {",
      "  client.transfer(&to, &amount);",
      "  env.require_auth(&to);",
      "}",
    ].join("\n");

    const findings = MissingRequireAuthPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("gated_last");
  });

  it("keeps fallback behavior on malformed source (no crash, finding survives)", () => {
    const code = [
      "impl Vault {",
      "  fn payout(env: Env, to: Address) {",
      "    client.transfer(&to, &amount);",
      "    env.require_auth(&to);",
      "  }",
    ].join("\n"); // unclosed brace: tree has errors, text fallback applies

    const findings = MissingRequireAuthPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("payout");
  });

  it("fixture: only gated_last is reported in the ordering fixture", () => {
    const code = fs.readFileSync(
      path.join(ROOT, "fixtures", "edge-cases", "auth_ordering.rs"),
      "utf-8",
    );

    const findings = new AuditEngine(createDefaultRegistry()).run(code);
    const auth = findings.filter((f) => f.id === "AP-AUTH-001");

    expect(auth).toHaveLength(1);
    expect(auth[0]?.location.function).toBe("gated_last");
    expect(auth[0]?.location.column).toBeGreaterThan(0);
    // No other rule may fire on this fixture.
    expect(findings).toHaveLength(1);
  });
});

describe("AP-AUTH-001 realistic Soroban patterns", () => {
  it("auth inside a nested block before the operation still gates it", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  if amount > 0 {",
      "    env.require_auth(&to);",
      "  }",
      "  client.transfer(&to, &amount);",
      "}",
    ].join("\n");

    // Positional heuristic: the auth call appears before the operation in
    // the body text, which is the documented (conservative-for-silence)
    // behavior for nested blocks.
    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(0);
  });

  it("operation inside a nested block before any auth is reported", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  if amount > 0 {",
      "    client.transfer(&to, &amount);",
      "  }",
      "  env.require_auth(&to);",
      "}",
    ].join("\n");

    const findings = MissingRequireAuthPlugin.scan(code);
    expect(findings).toHaveLength(1);
  });

  it("a commented-out require_auth does not gate anything", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  // env.require_auth(&to);  // TODO restore gating",
      "  client.transfer(&to, &amount);",
      "}",
    ].join("\n");

    const findings = MissingRequireAuthPlugin.scan(code);
    expect(findings).toHaveLength(1);
  });

  it("require_auth text inside a string literal does not gate anything", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      '  let note = "call require_auth(&to) first";',
      "  client.transfer(&to, &amount);",
      "}",
    ].join("\n");

    const findings = MissingRequireAuthPlugin.scan(code);
    expect(findings).toHaveLength(1);
  });

  it("an early sensitive operation is reported even when a later one is gated", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  client.transfer(&to, &amount);",
      "  env.require_auth(&to);",
      "  client.burn(&to, &amount);",
      "}",
    ].join("\n");

    // One finding per function: the first operation runs before any auth.
    const findings = MissingRequireAuthPlugin.scan(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("payout");
  });

  it("all operations gated when auth comes first", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  env.require_auth(&to);",
      "  client.transfer(&to, &amount);",
      "  client.burn(&to, &amount);",
      "}",
    ].join("\n");

    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(0);
  });

  it("documents the helper-function limitation: auth in a callee does not gate the caller", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  Self::authorize(&env, &to);",
      "  client.transfer(&to, &amount);",
      "}",
    ].join("\n");

    // Known limitation, not a bug: cross-function reasoning is not
    // implemented, so a helper-based auth boundary is invisible and the
    // finding fires. A correct broader location is preferred over guessing.
    const findings = MissingRequireAuthPlugin.scan(code);
    expect(findings).toHaveLength(1);
  });

  it("receiver-form admin.require_auth() gates subsequent operations", () => {
    const code = [
      "fn set_fee(env: Env, admin: Address, fee: u32) {",
      "  admin.require_auth();",
      "  env.storage().instance().set(&KEY_FEE, &fee);",
      "}",
    ].join("\n");

    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(0);
  });

  it("caller stays silent when gated by an intra-file pure auth helper", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  Self::authorize(&env, &to);",
      "  client.transfer(&to, &amount);",
      "}",
      "",
      "fn authorize(env: &Env, to: &Address) {",
      "  env.require_auth(to);",
      "}",
    ].join("\n");

    const findings = MissingRequireAuthPlugin.scan(code);
    expect(findings).toHaveLength(0);
  });

  it("auth helper works when defined after its usage in the caller", () => {
    const code = [
      "fn withdraw(env: Env, user: Address, amount: i128) {",
      "  check_auth(&user);",
      "  client.burn(&user, &amount);",
      "}",
      "",
      "fn check_auth(user: &Address) {",
      "  user.require_auth();",
      "}",
    ].join("\n");

    const findings = MissingRequireAuthPlugin.scan(code);
    expect(findings).toHaveLength(0);
  });

  it("helper containing non-auth statements does not gate the caller", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  Self::authorize_impure(&env, &to);",
      "  client.transfer(&to, &amount);",
      "}",
      "",
      "fn authorize_impure(env: &Env, to: &Address) {",
      "  let note = 1;",
      "  env.require_auth(to);",
      "}",
    ].join("\n");

    const findings = MissingRequireAuthPlugin.scan(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("payout");
  });

  it("helper called after the sensitive operation does not retroactively gate it", () => {
    const code = [
      "fn payout(env: Env, to: Address, amount: i128) {",
      "  client.transfer(&to, &amount);",
      "  Self::authorize(&env, &to);",
      "}",
      "",
      "fn authorize(env: &Env, to: &Address) {",
      "  env.require_auth(to);",
      "}",
    ].join("\n");

    const findings = MissingRequireAuthPlugin.scan(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("payout");
  });

  it("fixtures: safe auth-gated file stays clean, vulnerable file reports precisely", () => {
    const safe = fs.readFileSync(
      path.join(ROOT, "fixtures", "safe", "auth_gated.rs"),
      "utf-8",
    );
    const vulnerable = fs.readFileSync(
      path.join(ROOT, "fixtures", "vulnerable", "auth_after_operation.rs"),
      "utf-8",
    );
    const engine = () => new AuditEngine(createDefaultRegistry());

    expect(engine().run(safe)).toEqual([]);

    const findings = engine().run(vulnerable);
    const auth = findings.filter((f) => f.id === "AP-AUTH-001");
    const calls = findings.filter((f) => f.id === "AP-CALL-001");
    expect(auth).toHaveLength(2);
    expect(auth.map((f) => f.location.function).sort()).toEqual([
      "late_auth",
      "no_auth",
    ]);
    // late_auth has require_auth (albeit late), so only no_auth trips
    // AP-CALL-001.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.location.function).toBe("no_auth");
  });
});
