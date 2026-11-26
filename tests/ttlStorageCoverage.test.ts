import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import { parseRust } from "../src/parser/rust";
import type { Vulnerability } from "../src/types";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONTRACT = path.join(ROOT, "contracts", "TtlStorageCoverage.rs");

function readContract(): string {
  return fs.readFileSync(CONTRACT, "utf-8");
}

function ttlFindings(code: string): Vulnerability[] {
  return new AuditEngine(createDefaultRegistry())
    .run(code)
    .filter((finding) => finding.id === "AP-STORAGE-001");
}

function scanPlugin(code: string): Vulnerability[] {
  return MissingExtendTtlPlugin.scan(code);
}

describe("AP-STORAGE-001 storage-kind and key coverage", () => {
  it("accepts the new mixed-tier contract as syntactically valid Rust", () => {
    const parsed = parseRust(readContract());

    expect(parsed).not.toBeNull();
    expect(parsed?.hasError).toBe(false);
  });

  it("does not let a temporary extension mask an unextended persistent entry", () => {
    const code = readContract();
    const expectedLine =
      code.split("\n").findIndex((line) => line.includes("persistent().set")) + 1;
    const findings = ttlFindings(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("persist_balance");
    expect(findings[0]?.location.line).toBe(expectedLine);
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.confidence).toBe("medium");
    expect(findings[0]?.message).toContain("persistent");
    expect(findings[0]?.message).toContain("storage entry `key`");
  });

  it("does not let an extension for a different key mask the access", () => {
    const code = [
      "fn read_balance(env: Env, owner: Address) {",
      "  env.storage().persistent().set(&DataKey::Balance(owner.clone()), &1);",
      "  env.storage().persistent().extend_ttl(&DataKey::Config, 100, 200);",
      "}",
    ].join("\n");

    const findings = scanPlugin(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.line).toBe(2);
    expect(findings[0]?.message).toContain("DataKey::Balance(owner)");
  });

  it("matches an extension after normalizing clone and whitespace", () => {
    const code = [
      "fn read_balance(env: Env, owner: Address) {",
      "  env.storage().persistent().set(&DataKey::Balance(owner.clone()), &1);",
      "  env",
      "    .storage()",
      "    .persistent()",
      "    .extend_ttl(&DataKey::Balance(owner), 100, 200);",
      "}",
    ].join("\n");

    expect(scanPlugin(code)).toEqual([]);
  });

  it("does not accept a TTL call that appears only in a string literal", () => {
    const code = [
      "fn note_only(env: Env, key: Symbol) {",
      "  let note = \"env.storage().persistent().extend_ttl(&key, 100, 200)\";",
      "  env.storage().persistent().set(&key, &1);",
      "  let _ = note;",
      "}",
    ].join("\n");

    expect(scanPlugin(code)).toHaveLength(1);
  });

  it("does not require TTL for entries that are only removed", () => {
    const code = [
      "fn clear(env: Env, key: Symbol) {",
      "  env.storage().temporary().remove(&key);",
      "}",
    ].join("\n");

    expect(scanPlugin(code)).toEqual([]);
  });

  it("recognizes get_extended as a read that refreshes TTL", () => {
    const code = [
      "fn read(env: Env, key: Symbol) -> Option<i128> {",
      "  env.storage().persistent().get_extended(&key)",
      "}",
    ].join("\n");

    expect(scanPlugin(code)).toEqual([]);
  });

  it("recognizes threshold extension and try_update as an access", () => {
    const uncovered = [
      "fn update(env: Env, key: Symbol) {",
      "  env.storage().temporary().try_update(&key, |value| value);",
      "}",
    ].join("\n");
    const covered = [
      "fn update(env: Env, key: Symbol) {",
      "  env.storage().temporary().try_update(&key, |value| value);",
      "  env.storage().temporary().extend_ttl_to_threshold(&key, 100);",
      "}",
    ].join("\n");

    expect(scanPlugin(uncovered)).toHaveLength(1);
    expect(scanPlugin(covered)).toEqual([]);
  });

  it("retains conservative coverage for a storage-resolved bare key", () => {
    const code = [
      "fn refresh(env: Env, owner: Address) {",
      "  let key = DataKey::Balance(owner);",
      "  env.storage().persistent().set(&key, &1);",
      "  Self::extend(&env, key);",
      "}",
      "fn extend(env: &Env, key: DataKey) {",
      "  env.storage().persistent().extend_ttl(&key, 100, 200);",
      "}",
    ].join("\n");

    expect(scanPlugin(code)).toEqual([]);
  });
});
