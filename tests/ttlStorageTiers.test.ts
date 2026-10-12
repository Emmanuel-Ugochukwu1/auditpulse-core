import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import type { Vulnerability } from "../src/types";

const ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

function scan(code: string): Vulnerability[] {
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function scanContract(name: string): Vulnerability[] {
  return scan(fs.readFileSync(path.join(ROOT, "contracts", name), "utf-8"));
}

function readContract(name: string): string {
  return fs.readFileSync(path.join(ROOT, "contracts", name), "utf-8");
}

describe("contracts/TtlStorageTiers.rs — unmanaged tier", () => {
  it("triggers AP-STORAGE-001 exactly once", () => {
    const storage = scanContract("TtlStorageTiers.rs").filter(
      (f) => f.id === "AP-STORAGE-001",
    );

    expect(storage).toHaveLength(1);
    expect(storage[0]?.severity).toBe("high");
    expect(storage[0]?.message).toContain("extend_ttl");
    expect(storage[0]?.remediation).toContain("extend_ttl");
  });

  it("covers both storage tiers and bumps neither", () => {
    // Guards the fixture itself: both tiers must be exercised and no bumping
    // call may appear, otherwise the edge case it claims to cover is not real.
    const code = readContract("TtlStorageTiers.rs").replace(/\/\/[^\n]*/g, "");
    expect(code).toContain(".persistent()");
    expect(code).toContain(".temporary()");
    expect(code).not.toContain("extend_ttl");
    expect(code).not.toContain("get_extended");
  });

  it("also surfaces AP-ERROR-001 for the expired-read .unwrap()", () => {
    expect(scanContract("TtlStorageTiers.rs").map((f) => f.id)).toContain(
      "AP-ERROR-001",
    );
  });
});

describe("contracts/TtlStorageManaged.rs — managed tier", () => {
  it("produces no AP-STORAGE-001 finding", () => {
    const storage = scanContract("TtlStorageManaged.rs").filter(
      (f) => f.id === "AP-STORAGE-001",
    );
    expect(storage).toHaveLength(0);
  });

  it("keeps both tiers alive with extend_ttl / extend_ttl_to_threshold", () => {
    const code = readContract("TtlStorageManaged.rs");
    expect(code).toContain(".extend_ttl(");
    expect(code).toContain("extend_ttl_to_threshold(");
  });
});

describe("MissingExtendTtlPlugin — tier-specific edge cases", () => {
  it("flags a persistent-only access with no extend_ttl", () => {
    const code = `
      fn save(env: Env, key: Symbol) {
        env.storage().persistent().set(&key, &1);
      }
    `;
    const found = MissingExtendTtlPlugin.scan(code);
    expect(found).toHaveLength(1);
    expect(found[0]?.id).toBe("AP-STORAGE-001");
  });

  it("flags a temporary-only access with no extend_ttl", () => {
    const code = `
      fn touch(env: Env, key: Symbol) {
        env.storage().temporary().set(&key, &1);
      }
    `;
    const found = MissingExtendTtlPlugin.scan(code);
    expect(found).toHaveLength(1);
  });

  it("stays silent when only extend_ttl_to_threshold is present", () => {
    const code = `
      fn touch(env: Env, key: Symbol) {
        env.storage().temporary().set(&key, &1);
        env.storage().temporary().extend_ttl_to_threshold(&key, 50, 100);
      }
    `;
    expect(MissingExtendTtlPlugin.scan(code)).toEqual([]);
  });

  it("stays silent when get_extended is used", () => {
    const code = `
      fn read(env: Env, key: Symbol) -> u32 {
        env.storage().persistent().get_extended(&key).unwrap_or(0)
      }
    `;
    expect(MissingExtendTtlPlugin.scan(code)).toEqual([]);
  });

  it("does not flag a file that never touches storage", () => {
    const code = `
      fn add(a: i128, b: i128) -> i128 { a + b }
    `;
    expect(MissingExtendTtlPlugin.scan(code)).toEqual([]);
  });
});
