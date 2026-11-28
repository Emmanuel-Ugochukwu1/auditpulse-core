import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import MissingRequireAuthPlugin from "../src/plugins/missingRequireAuth";
import UnvalidatedExternalCallPlugin from "../src/plugins/unvalidatedExternalCall";
import { extractRustFunctions } from "../src/utils/rust";
import { extractRustFunctionsAst } from "../src/parser/rust";

// Functions stamped out by macro_rules! used to be invisible to the
// scanner: the text extractor skipped macro bodies wholesale, and to
// tree-sitter the whole body is just a token tree. These tests pin the
// fix - a generated function is analysed like any other function, and
// findings point at the definition inside the macro, which is the code
// a reviewer can actually change.

const macroVault = fs.readFileSync(
  path.join(__dirname, "..", "contracts", "MacroVault.rs"),
  "utf8",
);

describe("detection across macro expansions", () => {
  it("flags the unauthenticated transfer in a macro-generated function", () => {
    const findings = MissingRequireAuthPlugin.scan(macroVault);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-AUTH-001");
    expect(findings[0]?.location.function).toBe("payout");
    // `pub fn payout` sits on line 16 of the sample contract, inside the
    // macro body - not at the make_payout!() call site.
    expect(findings[0]?.location.line).toBe(16);
  });

  it("flags the unvalidated external call in the same generated function", () => {
    const findings = UnvalidatedExternalCallPlugin.scan(macroVault);

    expect(findings.map((f) => f.id)).toContain("AP-CALL-001");
    expect(findings[0]?.location.function).toBe("payout");
  });

  it("extracts generated functions in the text fallback, with real line numbers", () => {
    const fns = extractRustFunctions(macroVault);

    expect(fns.map((f) => f.name)).toEqual(["payout"]);
    expect(fns[0]?.line).toBe(16);
    expect(fns[0]?.body).toContain("client.transfer");
  });

  it("extracts generated functions from the tree-sitter tree too", () => {
    const fns = extractRustFunctionsAst(macroVault);

    expect(fns).not.toBeNull();
    expect(fns!.map((f) => f.name)).toEqual(["payout"]);
    expect(fns![0]?.line).toBe(16);
  });

  it("stays quiet when the generated function does call require_auth", () => {
    const code = `
      macro_rules! make_close {
        () => {
          pub fn close(env: Env, who: Address) {
            who.require_auth();
            env.storage().persistent().remove(&who);
          }
        };
      }
    `;

    expect(MissingRequireAuthPlugin.scan(code)).toHaveLength(0);
  });

  it("does not invent functions for macros that generate none", () => {
    const code = `
      macro_rules! log_payout {
        ($env:expr, $amount:expr) => {
          log!($env, "paid", $amount);
        };
      }
    `;

    expect(extractRustFunctions(code)).toEqual([]);
    expect(extractRustFunctionsAst(code)).toEqual([]);
  });
});
