import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { parseRust, extractFunctions } from "../src/parser/rust";
import type { Vulnerability } from "../src/types";

// Unit tests for GitHub issue #3: test fixtures for edge-case TTL and
// storage expirations. AP-STORAGE-001 is a file-level rule: it fires once
// when a file touches ledger storage and no `extend_ttl` call appears
// anywhere in the file. These tests pin how that rule behaves across
// Soroban's storage tiers (temporary / persistent / instance), which is
// where the edge cases live.

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

function scanRel(relPath: string): Vulnerability[] {
  const code = fs.readFileSync(path.join(ROOT, relPath), "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function idsOf(findings: Vulnerability[]): string[] {
  return findings.map((f) => f.id).sort();
}

describe("issue #3: TTL / storage-expiration edge cases", () => {
  it("temporary storage with no extend_ttl anywhere fires AP-STORAGE-001 exactly once", () => {
    const findings = scanRel("fixtures/edge-cases/ttl_temporary_unextended.rs");
    const storage = findings.filter((f) => f.id === "AP-STORAGE-001");

    expect(storage).toHaveLength(1);
    expect(storage[0]?.severity).toBe("high");
    // The single finding is reported at the first storage access.
    expect(storage[0]?.location.function).toBe("stash");
    // Both writers are auth-gated, so no other rule may fire on this file.
    expect(idsOf(findings)).toEqual(["AP-STORAGE-001"]);
  });

  it("extending one tier masks an unextended entry in another tier (file-level rule)", () => {
    // save_balance extends its persistent entry; cache_quote's temporary
    // entry is never extended. Because the rule only checks whether an
    // extend_ttl call exists in the file, it stays silent — this pins the
    // masking edge case a per-tier rule would need to fix.
    const findings = scanRel("fixtures/edge-cases/ttl_extended_other_tier.rs");

    expect(findings.filter((f) => f.id === "AP-STORAGE-001")).toEqual([]);
    expect(idsOf(findings)).toEqual([]);
  });

  it("the sample contract under contracts/ mixes tiers and stays clean", () => {
    const findings = scanRel("contracts/StorageTtlEdgeCases.rs");

    // Persistent and instance entries are extended, so the storage rule
    // is silent; the unextended temporary write in open_session is the
    // masked edge case documented in the contract header.
    expect(findings.filter((f) => f.id === "AP-STORAGE-001")).toEqual([]);
    expect(idsOf(findings)).toEqual([]);
  });

  it("the sample contract parses cleanly and exposes every tier's function", () => {
    const code = fs.readFileSync(
      path.join(ROOT, "contracts", "StorageTtlEdgeCases.rs"),
      "utf-8",
    );
    const parsed = parseRust(code);

    expect(parsed).not.toBeNull();
    expect(parsed!.hasError).toBe(false);
    expect(extractFunctions(parsed!.tree).map((fn) => fn.name)).toEqual([
      "save_profile",
      "open_session",
      "touch_instance",
      "read_profile",
    ]);
  });
});
