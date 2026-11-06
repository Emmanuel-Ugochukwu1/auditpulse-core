import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import type { Vulnerability } from "../src/types";

/**
 * TTL edge cases: temporary vs persistent storage extensions.
 *
 * `AP-STORAGE-001` is a file-level rule. It reports once when a file touches
 * `env.storage()` and calls none of `extend_ttl`, `extend_ttl_to_threshold`,
 * or `get_extended` anywhere, and points at the first storage access. These
 * tests pin the three sanctioned ways to keep an entry alive, the single-call
 * granularity, and what does *not* count as an extension.
 */

const CONTRACTS_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
);

function scan(code: string): Vulnerability[] {
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function ttlFindings(code: string): Vulnerability[] {
  return scan(code).filter((finding) => finding.id === "AP-STORAGE-001");
}

describe("AP-STORAGE-001 on the temporary/persistent fixture contract", () => {
  const contractPath = path.join(CONTRACTS_ROOT, "TtlEdgeCases.rs");

  it("the checked-in fixture exists and is scanned without findings", () => {
    expect(fs.existsSync(contractPath)).toBe(true);

    const code = fs.readFileSync(contractPath, "utf-8");
    const findings = scan(code);

    // Every storage access in this contract is accompanied by an extension,
    // and the contract is otherwise clean (explicit auth, checked math), so a
    // full scan yields nothing. Prove the file really does touch both storage
    // kinds and call each extension API, otherwise the assertion below could
    // pass on a file that does nothing at all.
    expect(code).toMatch(/env\.storage\(\)\.persistent\(\)/);
    expect(code).toMatch(/env\.storage\(\)\.temporary\(\)/);
    expect(code).toMatch(/\.extend_ttl\(/);
    expect(code).toMatch(/\.extend_ttl_to_threshold\(/);
    expect(code).toMatch(/\.get_extended\(/);

    expect(findings).toEqual([]);
  });
});

describe("AP-STORAGE-001 extension recognition", () => {
  it("accepts a persistent write followed by extend_ttl", () => {
    const code = `
      fn deposit(env: Env, user: Address, amount: i128) {
        let storage = env.storage().persistent();
        storage.set(&user, &amount);
        storage.extend_ttl(&user, 100, 200);
      }
    `;

    expect(ttlFindings(code)).toHaveLength(0);
  });

  it("accepts temporary storage kept alive by extend_ttl_to_threshold", () => {
    const code = `
      fn quote(env: Env, id: u32) -> u32 {
        let storage = env.storage().temporary();
        storage.set(&id, &1u32);
        storage.extend_ttl_to_threshold(&id, 50);
        1
      }
    `;

    expect(ttlFindings(code)).toHaveLength(0);
  });

  it("accepts a read-only path that uses get_extended", () => {
    const code = `
      fn peek(env: Env, user: Address) -> Option<i128> {
        env.storage().persistent().get_extended(&user)
      }
    `;

    expect(ttlFindings(code)).toHaveLength(0);
  });

  it("accepts instance storage extended by threshold without a key", () => {
    const code = `
      fn bump(env: Env) {
        env.storage().instance().extend_ttl(100, 1000);
      }
    `;

    expect(ttlFindings(code)).toHaveLength(0);
  });
});

describe("AP-STORAGE-001 reporting", () => {
  it("reports once at the first storage access when no extension exists", () => {
    const code = [
      "impl Vault {", // 1
      "  fn balance(env: Env, user: Address) -> i128 {", // 2
      "    env.storage().persistent().get(&user).unwrap_or(0)", // 3
      "  }", // 4
      "  fn total(env: Env) -> i128 {", // 5
      "    env.storage().instance().get(&K).unwrap_or(0)", // 6
      "  }", // 7
      "}", // 8
    ].join("\n");

    const findings = ttlFindings(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.confidence).toBe("medium");
    expect(findings[0]?.location).toEqual({
      line: 3,
      column: 3,
      function: "balance",
    });
  });

  it("does not treat a commented-out extend_ttl as an extension", () => {
    const code = `
      fn balance(env: Env, user: Address) -> i128 {
        // storage.extend_ttl(&user, 100, 200);
        env.storage().persistent().get(&user).unwrap_or(0)
      }
    `;

    const findings = ttlFindings(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("balance");
  });

  it("stays silent for files that never touch storage", () => {
    const code = `
      fn add(a: i128, b: i128) -> i128 {
        a + b
      }
    `;

    expect(ttlFindings(code)).toHaveLength(0);
  });

  it("silences the whole file when only one function extends its entry", () => {
    // Documented granularity: the rule is file-level, not per-function. A
    // single extension call anywhere is treated as evidence the author knows
    // the TTL requirement, even for sibling functions that omit it.
    const code = `
      fn deposited(env: Env, user: Address, amount: i128) {
        let storage = env.storage().persistent();
        storage.set(&user, &amount);
        storage.extend_ttl(&user, 100, 200);
      }

      fn cached_only(env: Env, id: u32) -> u32 {
        env.storage().temporary().get(&id).unwrap_or(0)
      }
    `;

    expect(ttlFindings(code)).toHaveLength(0);
  });
});

describe("AP-STORAGE-001 plugin surface", () => {
  it("exposes a stable rule identity for registry and reporting", () => {
    expect(MissingExtendTtlPlugin.id).toBe("AP-STORAGE-001");
    expect(MissingExtendTtlPlugin.name).toBe("Missing Extend TTL");
  });

  it("standalone scan() returns line-only locations without an AST", () => {
    const code = "fn broken( {\n  env.storage().persistent().get(&k);\n";

    const findings = MissingExtendTtlPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.line).toBe(2);
    expect(findings[0]?.location.column).toBeUndefined();
  });
});
