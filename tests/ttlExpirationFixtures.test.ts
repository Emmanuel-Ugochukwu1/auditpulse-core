import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import type { Vulnerability } from "../src/types";

/**
 * Fixture matrix for AP-STORAGE-001 (storage expiration / missing TTL bump).
 *
 * Beyond pinning the safe/vulnerable pair, this suite covers the edge cases
 * that used to change the rule's answer depending on how the code was
 * written:
 *
 * - string literals are not executable code: a `.extend_ttl(` hint inside a
 *   string must not silence the check (ttl_string_literals.rs), and a
 *   `storage().persistent()` phrase inside a string must not create a
 *   finding on its own (ttl_string_only.rs);
 * - access chains formatted across several lines must still be reported, at
 *   the `storage()` line where the access begins (ttl_multiline_chain.rs);
 * - lifetime-heavy signatures (`&'a`, `<'a>`) must not disturb the anchor
 *   (ttl_lifetimes.rs);
 * - comments never count as an implemented bump (ttl_comment_only.rs);
 * - the rule is file-level by design, so one bump anywhere silences the file
 *   (ttl_mixed_functions.rs) — pinned here so per-function granularity work
 *   has to update it deliberately;
 * - instance storage is currently in scope (ttl_instance_storage.rs), and
 *   the threshold-based extension API counts as a bump
 *   (ttl_alternate_extend_apis.rs).
 */

const FIXTURES_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "fixtures",
);

function scanFixture(relPath: string): Vulnerability[] {
  const code = fs.readFileSync(path.join(FIXTURES_ROOT, relPath), "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function storageFindings(findings: Vulnerability[]): Vulnerability[] {
  return findings.filter((f) => f.id === "AP-STORAGE-001");
}

describe("TTL / storage-expiration fixture matrix", () => {
  it("vulnerable/missing_extend_ttl.rs reports one file-level finding at the first access", () => {
    const findings = scanFixture("vulnerable/missing_extend_ttl.rs");
    const storage = storageFindings(findings);

    expect(storage).toHaveLength(1);
    expect(storage[0]?.severity).toBe("high");
    expect(storage[0]?.confidence).toBe("medium");
    expect(storage[0]?.location).toEqual({
      line: 16,
      column: 9,
      function: "load_balance",
    });
    expect(storage[0]?.message).toContain("extend_ttl");
    expect(storage[0]?.remediation).toContain("extend_ttl");
    // Nothing else in the file should fire.
    expect(findings.map((f) => f.id)).toEqual(["AP-STORAGE-001"]);
  });

  it("safe/ttl_extended_storage.rs stays silent", () => {
    expect(scanFixture("safe/ttl_extended_storage.rs")).toEqual([]);
  });

  it("ttl_comment_only.rs: commented-out bumps do not count", () => {
    const storage = storageFindings(
      scanFixture("edge-cases/ttl_comment_only.rs"),
    );

    expect(storage).toHaveLength(1);
    expect(storage[0]?.location.function).toBe("load");
  });

  it("ttl_string_literals.rs: a string hint neither suppresses the finding nor moves the anchor", () => {
    const storage = storageFindings(
      scanFixture("edge-cases/ttl_string_literals.rs"),
    );

    expect(storage).toHaveLength(1);
    // The anchor is the real access line, not the string line above it.
    expect(storage[0]?.location).toEqual({ line: 21, column: 9, function: "load" });
  });

  it("ttl_string_only.rs: a storage phrase inside a string alone is not a finding", () => {
    expect(
      storageFindings(scanFixture("edge-cases/ttl_string_only.rs")),
    ).toEqual([]);
  });

  it("ttl_lifetimes.rs: lifetime parameters keep the anchor intact", () => {
    const storage = storageFindings(
      scanFixture("edge-cases/ttl_lifetimes.rs"),
    );

    expect(storage).toHaveLength(1);
    expect(storage[0]?.location).toEqual({ line: 18, column: 9, function: "read_with" });
  });

  it("ttl_mixed_functions.rs: the rule is file-level, one bump silences the file", () => {
    // `forgetful` never bumps its entry, but `refresh` does and the rule is
    // documented as file-level. Pinned so a per-function granularity change
    // has to update this expectation on purpose.
    expect(scanFixture("edge-cases/ttl_mixed_functions.rs")).toEqual([]);
  });

  it("ttl_instance_storage.rs: instance-only access is in scope", () => {
    const storage = storageFindings(
      scanFixture("edge-cases/ttl_instance_storage.rs"),
    );

    expect(storage).toHaveLength(1);
    expect(storage[0]?.location).toEqual({ line: 17, column: 9, function: "counter" });
  });

  it("ttl_alternate_extend_apis.rs: threshold-based extensions count as bumps", () => {
    expect(scanFixture("edge-cases/ttl_alternate_extend_apis.rs")).toEqual([]);
  });

  it("ttl_multiline_chain.rs: chains split across lines are reported at the storage() line", () => {
    const storage = storageFindings(
      scanFixture("edge-cases/ttl_multiline_chain.rs"),
    );

    expect(storage).toHaveLength(1);
    expect(storage[0]?.location).toEqual({ line: 16, column: 9, function: "load" });
  });
});
