import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";

const CONTRACT_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
  "TtlEdgeCases.rs",
);

function scan(code: string) {
  return new AuditEngine(createDefaultRegistry()).run(code);
}

describe("contracts/TtlEdgeCases.rs", () => {
  it("produces no findings: TTL extension is present and setters are gated", () => {
    const code = fs.readFileSync(CONTRACT_PATH, "utf-8");
    const findings = scan(code);

    // extend_ttl + extend_ttl_to_threshold cover AP-STORAGE-001, and every
    // .set() is preceded by require_auth.
    expect(findings.map((f) => f.id)).toEqual([]);
  });
});

describe("temporary vs persistent TTL edge cases", () => {
  it("flags temporary storage written with no TTL extension anywhere", () => {
    const code = `
      use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

      #[contract]
      pub struct Sessions;

      #[contractimpl]
      impl Sessions {
          pub fn open(env: Env, user: Address, data: i128) {
              user.require_auth();
              let key = Symbol::new(&env, "session");
              env.storage().temporary().set(&key, &data);
          }
      }
    `;
    const findings = scan(code);

    expect(findings.map((f) => f.id)).toEqual(["AP-STORAGE-001"]);
  });

  it("still flags when the only extend_ttl sits inside a comment", () => {
    const code = `
      use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

      #[contract]
      pub struct Sessions;

      #[contractimpl]
      impl Sessions {
          // callers must remember to env.storage().temporary().extend_ttl(...)
          pub fn open(env: Env, user: Address, data: i128) {
              user.require_auth();
              let key = Symbol::new(&env, "session");
              env.storage().temporary().set(&key, &data);
          }
      }
    `;
    const findings = scan(code);

    expect(findings.map((f) => f.id)).toContain("AP-STORAGE-001");
  });
});
