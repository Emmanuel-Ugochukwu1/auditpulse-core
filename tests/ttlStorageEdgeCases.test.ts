import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import { parseRust } from "../src/parser/rust";
import { removeComments } from "../src/utils/rust";
import type { Vulnerability } from "../src/types";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

function read(relPath: string): string {
  return fs.readFileSync(path.join(ROOT, relPath), "utf-8");
}

function scan(relPath: string): Vulnerability[] {
  return new AuditEngine(createDefaultRegistry()).run(read(relPath));
}

function ttl(findings: Vulnerability[]): Vulnerability[] {
  return findings.filter((f) => f.id === "AP-STORAGE-001");
}

function firstStorageLine(code: string): number {
  const clean = removeComments(code);
  return clean.split("\n").findIndex((line) => /storage\s*\(\s*\)\s*\./.test(line)) + 1;
}

describe("TTL storage edge cases", () => {
  describe("contracts/TtlStorageUnmanaged.rs", () => {
    it("is valid Rust", () => {
      const parsed = parseRust(read("contracts/TtlStorageUnmanaged.rs"));

      expect(parsed).not.toBeNull();
      expect(parsed!.hasError).toBe(false);
    });

    it("reports the first unmanaged access exactly once", () => {
      const code = read("contracts/TtlStorageUnmanaged.rs");
      const findings = ttl(scan("contracts/TtlStorageUnmanaged.rs"));

      expect(findings).toHaveLength(1);
      const [finding] = findings;
      expect(finding?.id).toBe("AP-STORAGE-001");
      expect(finding?.severity).toBe("high");
      expect(finding?.confidence).toBe("medium");
      expect(finding?.message).toContain("extend_ttl");
      expect(finding?.remediation).toContain("extend_ttl");
      expect(finding?.location.function).toBe("persistent_balance");
      expect(finding?.location.line).toBe(firstStorageLine(code));
    });

    it("covers both persistent and temporary storage in the fixture", () => {
      const code = read("contracts/TtlStorageUnmanaged.rs");

      expect(code).toMatch(/\.persistent\(\)/);
      expect(code).toMatch(/\.temporary\(\)/);
      // File-level rule: one finding for the file, not one per storage kind.
      expect(ttl(scan("contracts/TtlStorageUnmanaged.rs"))).toHaveLength(1);
    });
  });

  describe("contracts/TtlStorageManaged.rs", () => {
    it("is valid Rust", () => {
      const parsed = parseRust(read("contracts/TtlStorageManaged.rs"));

      expect(parsed).not.toBeNull();
      expect(parsed!.hasError).toBe(false);
    });

    it("stays silent when every access is extended", () => {
      const code = read("contracts/TtlStorageManaged.rs");

      expect(code).toMatch(/\.extend_ttl\s*\(/);
      expect(code).toMatch(/extend_ttl_to_threshold\s*\(/);
      expect(code).toMatch(/get_extended\s*\(/);
      expect(ttl(scan("contracts/TtlStorageManaged.rs"))).toEqual([]);
    });
  });

  describe("extension forms", () => {
    it("accepts each recognised extension call", () => {
      const extensions = [
        "env.storage().persistent().extend_ttl(&key, 100, 200);",
        "env.storage().persistent().extend_ttl_to_threshold(&key, Threshold::Persistent);",
        "env.storage().persistent().get_extended(&key);",
      ];

      for (const extension of extensions) {
        const code = [
          "fn save(env: Env, key: Symbol) {",
          "  env.storage().persistent().set(&key, &1);",
          `  ${extension}`,
          "}",
        ].join("\n");

        expect(MissingExtendTtlPlugin.scan(code)).toEqual([]);
      }
    });

    it("still flags a real access when a comment mentions extend_ttl", () => {
      const code = [
        "fn save(env: Env, key: Symbol) {",
        "  // env.storage().persistent().extend_ttl(&key, 1, 2);",
        "  env.storage().persistent().set(&key, &1);",
        "}",
      ].join("\n");

      const findings = MissingExtendTtlPlugin.scan(code);

      expect(findings).toHaveLength(1);
      expect(findings[0]?.location.line).toBe(3);
    });
  });

  describe("fixtures/edge-cases", () => {
    it("ttl_extension_scope.rs pins the file-level scope", () => {
      // managed() extends its own key, unmanaged() does not. The extension
      // in managed() suppresses the whole file today; a function-level rule
      // would report unmanaged(). This test locks in the current behaviour.
      expect(ttl(scan("fixtures/edge-cases/ttl_extension_scope.rs"))).toEqual([]);
    });

    it("ttl_wrong_key_kind.rs pins the unmatched-extension behaviour", () => {
      // The extension targets a different key and storage kind. The rule
      // only checks that an extension exists, so it stays silent.
      expect(ttl(scan("fixtures/edge-cases/ttl_wrong_key_kind.rs"))).toEqual([]);
    });
  });
});
