import { describe, expect, it } from "vitest";
import MissingRequireAuthPlugin from "../src/plugins/missingRequireAuth";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import UnvalidatedExternalCallPlugin from "../src/plugins/unvalidatedExternalCall";

describe("local macro_rules! invocation awareness", () => {
  it("detects a sensitive storage write hidden behind an invoked macro", () => {
    const code = `
      macro_rules! write_balance {
        ($env:expr, $key:expr, $value:expr) => {{
          $env.storage().persistent().set(&$key, &$value);
        }};
      }

      fn update(env: Env, key: Symbol, amount: i128) {
        write_balance!(env, key, amount);
      }
    `;

    const auth = MissingRequireAuthPlugin.scan(code);
    expect(auth).toHaveLength(1);
    expect(auth[0]?.location.function).toBe("update");

    const ttl = MissingExtendTtlPlugin.scan(code);
    expect(ttl).toHaveLength(1);
    expect(ttl[0]?.location.function).toBe("update");
  });

  it("carries an authorization boundary from the invoked macro body", () => {
    const code = `
      macro_rules! authorized_write {
        ($env:expr, $user:expr, $key:expr, $value:expr) => {{
          $env.require_auth(&$user);
          $env.storage().persistent().set(&$key, &$value);
        }};
      }

      fn update(env: Env, user: Address, key: Symbol, amount: i128) {
        authorized_write!(env, user, key, amount);
      }
    `;

    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(0);
  });

  it("detects an external transfer hidden behind a macro invocation", () => {
    const code = `
      macro_rules! raw_transfer {
        ($client:expr, $to:expr, $amount:expr) => {{
          $client.transfer(&$to, &$amount);
        }};
      }

      fn payout(env: Env, to: Address, amount: i128) {
        let client = get_untrusted_client(&env);
        raw_transfer!(client, to, amount);
      }
    `;

    const findings = UnvalidatedExternalCallPlugin.scan(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("payout");
  });

  it("does not inspect an unsafe macro that is never invoked", () => {
    const code = `
      macro_rules! unused_write {
        ($env:expr, $key:expr, $value:expr) => {{
          $env.storage().persistent().set(&$key, &$value);
        }};
      }

      fn read_only(_env: Env) -> i128 {
        7
      }
    `;

    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(0);
    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
  });

  it("follows a bounded local macro-to-macro chain", () => {
    const code = `
      macro_rules! inner_write {
        ($env:expr, $key:expr, $value:expr) => {{
          $env.storage().persistent().set(&$key, &$value);
        }};
      }

      macro_rules! outer_write {
        ($env:expr, $key:expr, $value:expr) => {{
          inner_write!($env, $key, $value);
        }};
      }

      fn update(env: Env, key: Symbol, amount: i128) {
        outer_write!(env, key, amount);
      }
    `;

    const findings = MissingRequireAuthPlugin.scan(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("update");
  });
});
