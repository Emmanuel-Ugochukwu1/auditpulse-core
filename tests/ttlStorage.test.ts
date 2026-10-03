import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

function contract(name: string): string {
  return fs.readFileSync(path.join(ROOT, "contracts", name), "utf-8");
}

describe("TTL storage edge-case contracts", () => {
  it("accepts explicit TTL extension for persistent and temporary entries", () => {
    const code = contract("TtlStorageSafe.rs");

    expect(code).toContain("storage().persistent().extend_ttl");
    expect(code).toContain("storage().temporary().extend_ttl");
    expect(MissingExtendTtlPlugin.scan(code)).toEqual([]);
  });

  it("flags temporary storage writes that can expire without a TTL refresh", () => {
    const findings = MissingExtendTtlPlugin.scan(
      contract("TtlStorageMissingTemporary.rs"),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-STORAGE-001");
    expect(findings[0]?.message).toContain("persistent/temporary");
    expect(findings[0]?.location.line).toBeGreaterThan(0);
  });

  it("keeps conditional refresh logic recognized as TTL protection", () => {
    const code = contract("TtlStorageSafe.rs");

    expect(code).toContain("if env.storage().persistent().has");
    expect(code).toContain("if env.storage().temporary().has");
    expect(MissingExtendTtlPlugin.scan(code)).toHaveLength(0);
  });
});
