import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { scanTarget } from "../src/scanner";
import { defaultConfig } from "../src/config";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TTL_CONTRACT_PATH = path.join(ROOT, "contracts", "TtlExpirationVault.rs");
const LF = String.fromCharCode(10);

describe("AP-STORAGE-001 edge-case temporary vs. persistent TTL expirations", () => {
  it("flags contracts/TtlExpirationVault.rs at the first unextended temporary storage write", () => {
    const source = fs.readFileSync(TTL_CONTRACT_PATH, "utf-8");
    const engine = new AuditEngine(createDefaultRegistry());
    const findings = engine.run(source);
    const ttlFindings = findings.filter((f) => f.id === "AP-STORAGE-001");

    expect(ttlFindings).toHaveLength(1);
    expect(ttlFindings[0]?.severity).toBe("high");
    expect(ttlFindings[0]?.confidence).toBe("medium");
    expect(ttlFindings[0]?.location.function).toBe("record_temp_nonce");

    const report = scanTarget(TTL_CONTRACT_PATH, engine, defaultConfig());
    expect(report.filesScanned).toBe(1);
    expect(report.findings.some((f) => f.id === "AP-STORAGE-001")).toBe(true);
  });

  it("flags temporary storage in conditional/early-return branches when extend_ttl is absent", () => {
    const code = [
      "pub fn cache_quote(env: Env, active: bool, price: i128, key: Symbol) {",
      "    if !active {",
      "        return;",
      "    }",
      "    env.storage().temporary().set(&key, &price);",
      "}",
    ].join(LF);

    const findings = new AuditEngine(createDefaultRegistry()).run(code);
    const ttl = findings.filter((f) => f.id === "AP-STORAGE-001");
    expect(ttl).toHaveLength(1);
    expect(ttl[0]?.location.function).toBe("cache_quote");
    expect(ttl[0]?.location.line).toBe(5);
  });

  it("is not fooled by commented-out extend_ttl calls in line or block comments", () => {
    const code = [
      "pub fn touch_persistent(env: Env, key: Symbol) {",
      "    // env.storage().persistent().extend_ttl(&key, 50, 100);",
      "    /* extend_ttl_to_threshold(&env, &key); */",
      "    let _val: Option<u64> = env.storage().persistent().get(&key);",
      "}",
    ].join(LF);

    const findings = MissingExtendTtlPlugin.scan(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-STORAGE-001");
  });

  it("accepts extend_ttl, extend_ttl_to_threshold, and get_extended across temporary and persistent tiers", () => {
    const withTempExtend = [
      "pub fn bump_temp(env: Env, key: Symbol, v: u32) {",
      "    env.storage().temporary().set(&key, &v);",
      "    env.storage().temporary().extend_ttl(&key, 100, 500);",
      "}",
    ].join(LF);

    const withThresholdHelper = [
      "pub fn bump_persistent(env: Env, key: Symbol) -> Option<i128> {",
      "    let val = env.storage().persistent().get(&key);",
      "    extend_ttl_to_threshold(&env, &key, 1_000, 5_000);",
      "    val",
      "}",
    ].join(LF);

    const withGetExtended = [
      "pub fn read_extended(env: Env, key: Symbol) -> Option<i128> {",
      "    env.storage().persistent().get_extended(&key, 200, 400)",
      "}",
    ].join(LF);

    expect(MissingExtendTtlPlugin.scan(withTempExtend)).toEqual([]);
    expect(MissingExtendTtlPlugin.scan(withThresholdHelper)).toEqual([]);
    expect(MissingExtendTtlPlugin.scan(withGetExtended)).toEqual([]);
  });

  it("detects multiline chained storage() access with whitespace variations", () => {
    const code = [
      "pub fn multiline_access(env: Env, k: Symbol) {",
      "    env",
      "        .storage  (  )  .persistent()",
      "        .remove(&k);",
      "}",
    ].join(LF);

    const findings = new AuditEngine(createDefaultRegistry()).run(code);
    const ttl = findings.filter((f) => f.id === "AP-STORAGE-001");
    expect(ttl).toHaveLength(1);
    expect(ttl[0]?.location.function).toBe("multiline_access");
    expect(ttl[0]?.location.line).toBe(3);
  });
});
