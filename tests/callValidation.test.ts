import { describe, it, expect } from "vitest";
import UnvalidatedExternalCallPlugin from "../src/plugins/unvalidatedExternalCall";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";

/**
 * Tiered local validation analysis for AP-CALL-001 (AP-008).
 *
 * Intended behavior, defined before implementation:
 * - require_auth anywhere in the function suppresses the finding (presence
 *   based: AP-AUTH-001 owns the late-auth ordering problem, and this rule
 *   must not double-report the same root cause).
 * - An explicit check on an id-bearing value BEFORE the call suppresses the
 *   finding: assert!/require! or an equality comparison on the same line as
 *   the id, positioned before the sensitive call.
 * - An id-named parameter with no visible check is reported (medium
 *   confidence): the argument name is a convention, not validation. This
 *   fixes the old behavior where merely MENTIONING an *_id anywhere in the
 *   body suppressed the finding.
 * - An id-named local resolved from env.storage()...get is reported at low
 *   confidence with a storage-resolved (admin-controlled) message — the
 *   tier requested in GitHub issue #13.
 * - No visible boundary at all is reported exactly as before (low
 *   confidence, unchanged message).
 * - try_* results are NOT a validation boundary (the rule's doc comment
 *   already promised this; the code disagreed).
 */

const scan = (code: string) =>
  UnvalidatedExternalCallPlugin.scanFunction({
    name: "<test>",
    line: 1,
    endLine: 99,
    body: code,
    bodyInner: code.slice(code.indexOf("{") + 1),
    bodyLine: 1,
  });

const CALL = (id = "token_id") => `
    let client = token::Client::new(&env, &${id});
    client.transfer(&env.current_contract_address(), &to, &amount);
`;

describe("AP-CALL-001 tiered validation model", () => {
  it("stays silent when the id is explicitly checked before the call", () => {
    const code = `fn f(env: Env, token_id: Address, to: Address, amount: i128) {${CALL()}    }`;

    // Checked before use: equality against the expected value, before the call.
    expect(scan(`fn f() {\n    assert!(token_id == &expected);\n${CALL()}}`)).toEqual([]);
    expect(scan(`fn f() {\n    require!(token_id != &zero);\n${CALL()}}`)).toEqual([]);
  });

  it("reports an id-named parameter that is never checked (naming is not validation)", () => {
    const findings = scan(`fn f(env: Env, token_id: Address, to: Address) {${CALL()}}`);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-CALL-001");
    expect(findings[0]?.confidence).toBe("medium");
    expect(findings[0]?.message).toContain("token_id");
  });

  it("reports when the check happens only after the call", () => {
    // Validation text appears in the body, but after the sensitive call:
    // it cannot have gated it. The old code suppressed on the mere mention.
    const findings = scan(`fn f(env: Env, token_id: Address) {\n${CALL()}    assert!(token_id == &expected);\n}`);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.confidence).toBe("medium");
  });

  it("orders evidence per call: a later check does not gate an earlier call", () => {
    // Two calls; the check sits between them. The first call is ungated.
    const findings = scan(`fn f(env: Env, token_id: Address) {
    let client = token::Client::new(&env, &token_id);
    client.transfer(&a, &b, &c);
    assert!(token_id == &expected);
    client.burn(&a, &amount);
}`);

    expect(findings).toHaveLength(1);
  });

  it("recognizes checks inside nested control flow before the call", () => {
    const findings = scan(`fn f(env: Env, token_id: Address) {
    if authorized {
        assert!(token_id == &expected);
        client.transfer(&a, &b, &c);
    }
}`);

    expect(findings).toEqual([]);
  });

  it("treats storage-resolved ids as a weaker reported tier, not a boundary", () => {
    const findings = scan(`fn f(env: Env) {
    let token_id = env.storage().instance().get(&KEY).unwrap();
${CALL()}}`);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.confidence).toBe("low");
    expect(findings[0]?.message).toContain("storage");
  });

  it("treats a multi-line storage resolution as the storage tier too", () => {
    const findings = scan(`fn f(env: Env) {
    let token_id: Address = env
        .storage()
        .persistent()
        .get(&KEY)
        .unwrap();
${CALL()}}`);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.confidence).toBe("low");
    expect(findings[0]?.message).toContain("storage");
  });

  it("does not treat unwraps or panics as validation evidence", () => {
    // .unwrap() proves existence, not validity; panic! in a fallback path
    // likewise. Both must still report.
    for (const suffix of [".unwrap()", ".unwrap_or_else(|| panic!(\"missing\"))", ".ok_or(Error::Missing)?"]) {
      const findings = scan(`fn f(env: Env) {\n    let token_id = env.storage().instance().get(&KEY)${suffix};\n${CALL()}}`);

      expect(findings, suffix).toHaveLength(1);
    }
  });

  it("does not let a mere rename count as validation", () => {
    const findings = scan(`fn f(env: Env, token_id: Address) {\n    let target = token_id;\n${CALL("target")}}`);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.confidence).toBe("medium");
  });

  it("ignores commented-out validation", () => {
    const findings = scan(`fn f(env: Env, token_id: Address) {\n    // assert!(token_id == &expected);\n${CALL()}}`);

    expect(findings).toHaveLength(1);
  });

  it("ignores validation-like text inside string literals", () => {
    const findings = scan(`fn f(env: Env, token_id: Address) {\n    let note = "assert!(token_id == &expected)";\n${CALL()}}`);

    expect(findings).toHaveLength(1);
  });

  it("keeps require_auth suppression regardless of position", () => {
    expect(
      scan(`fn f(env: Env, token_id: Address) {\n${CALL()}    env.require_auth(&to);\n}`),
    ).toEqual([]);
    expect(
      scan(`fn f(env: Env, token_id: Address) {\n    env.require_auth(&to);\n${CALL()}}`),
    ).toEqual([]);
  });

  it("does not let a try_ call gate a sensitive call", () => {
    // The old code suppressed the finding whenever .try_* appeared anywhere
    // in the body, even though the rule header said try_ results are not a
    // boundary. A failed-attempt result proves nothing about validation.
    const findings = scan(`fn f(env: Env) {\n    let r = client.try_mint(&a, &b);\n    client.transfer(&env.current_contract_address(), &to, &amount);\n}`);

    expect(findings).toHaveLength(1);
  });

  it("leaves try_ calls outside the sensitive set", () => {
    // Prefer silence: a try_ call alone was never flagged and still is not.
    expect(scan(`fn f(env: Env) {\n    let r = client.try_transfer(&a, &b, &c);\n}`)).toEqual([]);
  });

  it("leaves the plain no-boundary finding exactly as before", () => {
    const findings = scan(`fn f(env: Env, token: Address, to: Address, amount: i128) {${CALL("token")}}`);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.confidence).toBe("low");
    expect(findings[0]?.message).toContain("no address validation or require_auth boundary");
  });
});

describe("AP-CALL-001 engine integration", () => {
  it("reports a user-supplied unchecked id through the engine", () => {
    const code = `
      fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
      }
    `;
    const findings = new AuditEngine(createDefaultRegistry()).run(code);
    const calls = findings.filter((f) => f.id === "AP-CALL-001");

    expect(calls).toHaveLength(1);
    expect(calls[0]?.confidence).toBe("medium");
  });

  it("keeps malformed-source fallback working", () => {
    const code = `fn broken( {\n  garbage\n}\n\nfn payout(env: Env, token: Address, to: Address, amount: i128) {\n    let client = token::Client::new(&env, &token);\n    client.transfer(&env.current_contract_address(), &to, &amount);\n}`;
    const findings = new AuditEngine(createDefaultRegistry()).run(code);

    expect(findings.map((f) => f.id)).toContain("AP-CALL-001");
  });

  it("provides expression-level line and column locations when AST coordinates are present", () => {
    const code = [
      "fn payout(env: Env, token_id: Address, to: Address, amount: i128) {", // 1
      "  let client = token::Client::new(&env, &token_id);",               // 2
      "  client.transfer(&to, &amount);",                                   // 3
      "}",                                                                  // 4
    ].join("\n");
    const findings = new AuditEngine(createDefaultRegistry()).run(code);
    const callFinding = findings.find((f) => f.id === "AP-CALL-001");

    expect(callFinding).toBeDefined();
    expect(callFinding?.location.function).toBe("payout");
    expect(callFinding?.location.line).toBe(3);
    expect(callFinding?.location.column).toBe(10);
  });
});
