import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { scanTarget } from "../src/scanner";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { defaultConfig } from "../src/config";
import MissingRequireAuthPlugin from "../src/plugins/missingRequireAuth";
import { macrosContaining } from "../src/utils/rust";

describe("Macro expansion detection (#2)", () => {
  it("scans contracts/MacroExpandedVault.rs and only flags the unguarded function", () => {
    const vaultPath = resolve("contracts/MacroExpandedVault.rs");
    const engine = new AuditEngine(createDefaultRegistry());
    const report = scanTarget(vaultPath, engine, defaultConfig());

    const authFindings = report.findings.filter((f) => f.id === "AP-AUTH-001");
    // Only unauthorized_transfer should be flagged.
    // withdraw_with_macro and emergency_drain are protected by macros.
    expect(authFindings).toHaveLength(1);
    expect(authFindings[0]?.location.function).toBe("unauthorized_transfer");
  });

  describe("macro_rules! authorization expansion", () => {
    it("extracts macro names containing require_auth calls", () => {
      const code = `
        macro_rules! gate {
          ($env:expr, $user:expr) => {
            $env.require_auth($user);
          };
        }
      `;
      const macros = macrosContaining(code, /require_auth/);
      expect(macros).toEqual(["gate"]);
    });

    it("recognizes local macro calls as valid auth gates", () => {
      const code = `
        macro_rules! auth_check {
          ($env:expr, $user:expr) => {
            $env.require_auth($user);
          };
        }

        fn payout(env: Env, to: Address, amount: i128) {
          auth_check!(&env, &to);
          let client = token::Client::new(&env, &token_id);
          client.transfer(&to, &amount);
        }
      `;
      const findings = MissingRequireAuthPlugin.scan(code);
      expect(findings).toHaveLength(0);
    });

    it("still flags operations if macro is called after sensitive operation", () => {
      const code = `
        macro_rules! auth_check {
          ($env:expr, $user:expr) => {
            $env.require_auth($user);
          };
        }

        fn late_auth(env: Env, to: Address, amount: i128) {
          let client = token::Client::new(&env, &token_id);
          client.transfer(&to, &amount);
          auth_check!(&env, &to);
        }
      `;
      const findings = MissingRequireAuthPlugin.scan(code);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.id).toBe("AP-AUTH-001");
    });
  });

  describe("Procedural attribute macro authorization", () => {
    it("treats #[only_owner] as an authorization boundary", () => {
      const code = `
        #[only_owner]
        fn drain(env: Env, to: Address, amount: i128) {
          let client = token::Client::new(&env, &token_id);
          client.transfer(&to, &amount);
        }
      `;
      const findings = MissingRequireAuthPlugin.scan(code);
      expect(findings).toHaveLength(0);
    });

    it("treats #[only_admin] as an authorization boundary", () => {
      const code = `
        #[only_admin]
        fn set_rate(env: Env, to: Address, amount: i128) {
          client.transfer(&to, &amount);
        }
      `;
      const findings = MissingRequireAuthPlugin.scan(code);
      expect(findings).toHaveLength(0);
    });
  });
});
