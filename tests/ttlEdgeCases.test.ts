import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";

const CONTRACTS_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
);

function scanContract(relPath: string) {
  const code = fs.readFileSync(path.join(CONTRACTS_ROOT, relPath), "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

describe("contracts/TtlEdgeCases.rs", () => {
  it("flags temporary + persistent storage that never extends TTL", () => {
    const findings = scanContract("TtlEdgeCases.rs");
    const ttl = findings.filter((f) => f.id === "AP-STORAGE-001");

    // File-level rule: exactly one finding, anchored at the first storage
    // access inside open_session.
    expect(ttl).toHaveLength(1);
    expect(ttl[0]?.severity).toBe("high");
    expect(ttl[0]?.location.function).toBe("open_session");
    expect(ttl[0]?.message).toContain("extend_ttl");
    expect(ttl[0]?.remediation).toContain("extend_ttl");
  });
});

describe("MissingExtendTtlPlugin edge cases (AP-STORAGE-001)", () => {
  it("flags temporary-only storage without any TTL bump", () => {
    const code = `
      fn open_session(env: Env, key: Symbol) {
        let store = env.storage().temporary();
        store.set(&key, &1u32);
      }
    `;

    const findings = MissingExtendTtlPlugin.scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-STORAGE-001");
    expect(findings[0]?.location.line).toBe(3);
  });

  it("accepts persistent storage bumped via extend_ttl", () => {
    const code = `
      fn record(env: Env, key: Symbol, value: i128) {
        let store = env.storage().persistent();
        store.set(&key, &value);
        store.extend_ttl(&key, 100, 200);
      }
    `;

    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
  });

  it("accepts extend_ttl_to_threshold and get_extended as TTL bumps", () => {
    const withThreshold = `
      fn a(env: Env, key: Symbol) {
        env.storage().persistent().extend_ttl_to_threshold(&key, 100);
      }
    `;
    const withGetExtended = `
      fn b(env: Env, key: Symbol) -> i128 {
        env.storage().persistent().get_extended(&key, 100, 200).unwrap()
      }
    `;

    expect(MissingExtendTtlPlugin.scan(withThreshold)).toHaveLength(0);
    expect(MissingExtendTtlPlugin.scan(withGetExtended)).toHaveLength(0);
  });

  it("ignores extend_ttl that only appears in comments", () => {
    const code = `
      fn record(env: Env, key: Symbol, value: i128) {
        let store = env.storage().persistent();
        store.set(&key, &value);
        // store.extend_ttl(&key, 100, 200); // TODO: re-enable before mainnet
      }
    `;

    // Comments are stripped before matching, so the commented-out bump
    // must not silence the rule.
    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(1);
  });

  it("documents the file-level limitation: a bump on a cold branch still silences the rule", () => {
    const code = `
      fn mixed(env: Env, key: Symbol, bump: bool, value: i128) {
        let store = env.storage().persistent();
        store.set(&key, &value);
        if bump {
          store.extend_ttl(&key, 100, 200);
        }
      }
    `;

    // The rule is intentionally file-level: any extend_ttl anywhere in
    // the file suppresses the finding, even on a conditional branch that
    // may never run. This test pins that behavior so a future,
    // branch-aware rule update is a deliberate change.
    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
  });
});
