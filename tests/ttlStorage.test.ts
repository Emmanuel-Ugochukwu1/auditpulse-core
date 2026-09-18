import { describe, it, expect } from "vitest";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import type { Vulnerability } from "../src/types";

function expectWellFormedFinding(finding: Vulnerability, id: string): void {
  expect(finding.id).toBe(id);
  expect(finding.severity).toBeTruthy();
  expect(finding.confidence).toBeTruthy();
  expect(finding.location.line).toBeGreaterThan(0);
  expect(finding.message.length).toBeGreaterThan(10);
  expect(finding.remediation).toBeTruthy();
  expect(finding.remediation!.length).toBeGreaterThan(10);
}

describe("MissingExtendTtlPlugin (AP-STORAGE-001)", () => {
  it("detects a temporary write with no extend_ttl", () => {
    const code = `
      fn open_session(env: Env, user: Address, token: Symbol) {
        env.storage().temporary().set(&DataKey::Session(user), &token);
      }
    `;

    const findings = MissingExtendTtlPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expectWellFormedFinding(findings[0]!, "AP-STORAGE-001");
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.location.function).toBe("open_session");
    expect(findings[0]?.location.line).toBe(3);
  });

  it("does not let a correct extend in one function mask a gap in another", () => {
    const code = `
      fn deposit(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set(&DataKey::Balance(user.clone()), &amount);
        env.storage().persistent().extend_ttl(&DataKey::Balance(user), T, E);
      }

      fn open_session(env: Env, user: Address, token: Symbol) {
        env.storage().temporary().set(&DataKey::Session(user), &token);
      }
    `;

    const findings = MissingExtendTtlPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("open_session");
  });

  it("flags a temporary write extended on persistent storage", () => {
    const code = `
      fn open_session(env: Env, user: Address, token: Symbol) {
        env.storage().temporary().set(&DataKey::Session(user.clone()), &token);
        env.storage().persistent().extend_ttl(&DataKey::Balance(user), T, E);
      }
    `;

    const findings = MissingExtendTtlPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("open_session");
    expect(findings[0]?.message).toContain("temporary");
  });

  it("flags an extension that bumps a different key in the same storage", () => {
    const code = `
      fn open_session(env: Env, user: Address, token: Symbol) {
        env.storage().temporary().set(&DataKey::Session(user), &token);
        env.storage().temporary().extend_ttl(&DataKey::Config, T, E);
      }
    `;

    const findings = MissingExtendTtlPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain("different key");
  });

  it("downgrades confidence when the extension is only on one branch", () => {
    const code = `
      fn conditional_extend(env: Env, user: Address, amount: i128, renew: bool) {
        env.storage().persistent().set(&DataKey::Balance(user.clone()), &amount);
        if renew {
          env.storage().persistent().extend_ttl(&DataKey::Balance(user), T, E);
        }
      }
    `;

    const findings = MissingExtendTtlPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.confidence).toBe("low");
  });

  it("ignores a matching extend on the same type and key", () => {
    const code = `
      fn deposit(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set(&DataKey::Balance(user.clone()), &amount);
        env.storage().persistent().extend_ttl(&DataKey::Balance(user), T, E);
      }
    `;

    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
  });

  it("ignores keyless instance storage extensions", () => {
    const code = `
      fn set_config(env: Env, value: Symbol) {
        env.storage().instance().set(&DataKey::Config, &value);
        env.storage().instance().extend_ttl(T, E);
      }
    `;

    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
  });

  it("ignores extensions delegated to a local helper", () => {
    const code = `
      fn deposit_via_helper(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set(&DataKey::Balance(user.clone()), &amount);
        Self::renew(&env, user);
      }

      fn renew(env: &Env, user: Address) {
        env.storage().persistent().extend_ttl(&DataKey::Balance(user), T, E);
      }
    `;

    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
  });

  it("ignores extend_ttl mentioned only in comments and strings", () => {
    const code = `
      fn documented_only(env: Env, user: Address, amount: i128) {
        // Remember to call extend_ttl before this expires.
        let _note = "extend_ttl";
        env.storage().persistent().extend_ttl(&DataKey::Balance(user), T, E);
        env.storage().persistent().set(&DataKey::Balance(user), &amount);
      }
    `;

    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
  });

  it("ignores removal-only access and non-Rust input", () => {
    const code = `
      fn clear(env: Env, user: Address) {
        env.storage().temporary().remove(&DataKey::Session(user));
      }
    `;

    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
    expect(MissingExtendTtlPlugin.scan("")).toHaveLength(0);
    expect(MissingExtendTtlPlugin.scan("plain text")).toHaveLength(0);
  });
});
