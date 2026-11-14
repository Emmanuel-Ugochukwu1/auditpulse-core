import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { removeComments } from "../src/utils/rust";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONTRACT = path.join(ROOT, "contracts", "StorageTtlEdgeCases.rs");

const TTL_ID = "AP-STORAGE-001";

/** Runs the full engine over `code` and keeps only the TTL rule's findings. */
function ttlFindings(code: string) {
  const findings = new AuditEngine(createDefaultRegistry()).run(code);
  return findings.filter((finding) => finding.id === TTL_ID);
}

/** First `storage().` line in comment-stripped code, 1-based. */
function firstStorageLine(code: string): number {
  const clean = removeComments(code);
  return (
    clean.split("\n").findIndex((line) => /storage\s*\(\s*\)\s*\./.test(line)) +
    1
  );
}

describe("contracts/StorageTtlEdgeCases.rs — TTL edge cases", () => {
  it("flags exactly one AP-STORAGE-001 at the first storage access", () => {
    const code = fs.readFileSync(CONTRACT, "utf-8");
    const findings = ttlFindings(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe(TTL_ID);
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.confidence).toBe("medium");
    // The rule reports the first storage access in the file, which is the
    // temporary-storage read in read_temp_without_bump.
    expect(findings[0]?.location.line).toBe(firstStorageLine(code));
    expect(findings[0]?.location.function).toBe("read_temp_without_bump");
  });

  it("temporary storage with extend_ttl is not flagged", () => {
    const code = `
      pub fn bump_temp(env: Env, key: Symbol) {
        env.storage().temporary().extend_ttl(&key, 100, 200);
      }
    `;
    expect(ttlFindings(code)).toHaveLength(0);
  });

  it("persistent storage with extend_ttl is not flagged", () => {
    const code = `
      pub fn bump_persistent(env: Env, key: Symbol) {
        env.storage().persistent().extend_ttl(&key, 100, 200);
      }
    `;
    expect(ttlFindings(code)).toHaveLength(0);
  });

  it("extend_ttl_to_threshold counts as a bump", () => {
    const code = `
      pub fn bump_threshold(env: Env, key: Symbol) {
        env.storage().temporary().extend_ttl_to_threshold(&key, 500);
      }
    `;
    expect(ttlFindings(code)).toHaveLength(0);
  });

  it("get_extended counts as a bump", () => {
    const code = `
      pub fn read_extended(env: Env, key: Symbol) -> Option<i128> {
        env.storage().persistent().get_extended(&key, 100, 200)
      }
    `;
    expect(ttlFindings(code)).toHaveLength(0);
  });

  it("no storage access is not flagged", () => {
    const code = `
      pub fn pure_add(a: i128, b: i128) -> i128 {
        a + b
      }
    `;
    expect(ttlFindings(code)).toHaveLength(0);
  });

  it("instance storage without extend_ttl is flagged", () => {
    const code = `
      pub fn read_instance(env: Env, key: Symbol) -> Option<Address> {
        env.storage().instance().get(&key)
      }
    `;
    const findings = ttlFindings(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("read_instance");
  });

  it("extend_ttl mentioned only in a comment does not suppress the finding", () => {
    const code = `
      pub fn commented_bump(env: Env, key: Symbol) -> Option<i128> {
        // extend_ttl would keep this alive, but the call is missing.
        env.storage().temporary().get(&key)
      }
    `;
    expect(ttlFindings(code)).toHaveLength(1);
  });

  it("extend_ttl inside a string literal suppresses the finding (known limitation)", () => {
    // The rule strips comments but not string contents, so an
    // extend_ttl written only inside a string counts as a bump.
    // This test documents the current behaviour; if the rule is later
    // taught to blank string contents, this expectation should flip
    // to one finding.
    const code = `
      pub fn string_bump(env: Env, key: Symbol) -> Option<i128> {
        let _note = "bump with env.storage().extend_ttl(&key, 100, 200)";
        env.storage().temporary().get(&key)
      }
    `;
    expect(ttlFindings(code)).toHaveLength(0);
  });
});
