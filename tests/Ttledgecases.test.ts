import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";

const CONTRACT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "contracts",
  "TtlEdgeCases.rs",
);

const source = fs.readFileSync(CONTRACT, "utf-8");
const engine = () => new AuditEngine(createDefaultRegistry());
const ttl = (code: string) => MissingExtendTtlPlugin.scan(code);

describe("contracts/TtlEdgeCases.rs (temporary vs. persistent TTL)", () => {
  it("reports exactly one AP-STORAGE-001 finding and nothing else", () => {
    const findings = engine().run(source);

    expect(findings.map((f) => f.id)).toEqual(["AP-STORAGE-001"]);
  });

  it("anchors the file-level finding at the first (temporary) storage access", () => {
    const finding = engine().run(source)[0];
    const expectedLine =
      source.split("\n").findIndex((l) => l.includes("storage().temporary().set")) + 1;

    expect(finding?.location.line).toBe(expectedLine);
    expect(finding?.location.function).toBe("set_session");
    expect(finding?.severity).toBe("high");
    expect(finding?.confidence).toBe("medium");
  });

  it("ignores extend_ttl mentioned only in line and block comments", () => {
    // Both the temporary and persistent extend_ttl calls in the contract are
    // commented out; neither may count as a bump.
    expect(source).toMatch(/\/\/.*temporary\(\)\.extend_ttl/);
    expect(source).toMatch(/\/\*.*persistent\(\)\.extend_ttl/);
    expect(ttl(source)).toHaveLength(1);
  });

  it("is clean once a real extend_ttl is added", () => {
    const fixed = source.replace(
      /\}\s*$/,
      `
    pub fn bump(env: Env, user: Address) {
        env.storage().persistent().extend_ttl(&DataKey::Balance(user), 100, 200);
    }
}
`,
    );

    expect(fixed).not.toBe(source);
    expect(ttl(fixed)).toHaveLength(0);
  });
});

describe("AP-STORAGE-001 storage-type edge cases", () => {
  it("flags temporary-only storage with no extension", () => {
    const code = `
      fn put(env: Env, k: Symbol, v: u64) {
        env.storage().temporary().set(&k, &v);
      }
    `;

    const findings = ttl(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.line).toBe(3);
  });

  it("flags persistent-only storage with no extension", () => {
    const code = `
      fn put(env: Env, k: Symbol, v: i128) {
        env.storage().persistent().set(&k, &v);
      }
    `;

    expect(ttl(code)).toHaveLength(1);
  });

  it("accepts each storage type extended with its own extend_ttl", () => {
    const temporary = `
      fn put(env: Env, k: Symbol, v: u64) {
        env.storage().temporary().set(&k, &v);
        env.storage().temporary().extend_ttl(&k, 10, 20);
      }
    `;
    const persistent = `
      fn put(env: Env, k: Symbol, v: i128) {
        env.storage().persistent().set(&k, &v);
        env.storage().persistent().extend_ttl(&k, 100, 200);
      }
    `;

    expect(ttl(temporary)).toHaveLength(0);
    expect(ttl(persistent)).toHaveLength(0);
  });

  it("accepts both storage types when each is extended", () => {
    const code = `
      fn put(env: Env, k: Symbol, v: i128) {
        env.storage().temporary().set(&k, &v);
        env.storage().temporary().extend_ttl(&k, 10, 20);
        env.storage().persistent().set(&k, &v);
        env.storage().persistent().extend_ttl_to_threshold(&k, 100, 200);
      }
    `;

    expect(ttl(code)).toHaveLength(0);
  });

  it("reports the first storage access even when it is persistent and later than a temporary read", () => {
    const code = `
      fn a(env: Env) {
        let x = 1;
      }
      fn b(env: Env, k: Symbol) {
        env.storage().persistent().get(&k);
        env.storage().temporary().get(&k);
      }
    `;

    const findings = ttl(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.line).toBe(6);
  });

  it("keeps the reported line accurate below a multi-line block comment", () => {
    const code = [
      "/* header",
      "   spanning",
      "   several lines */",
      "fn put(env: Env, k: Symbol, v: u64) {",
      "  env.storage().temporary().set(&k, &v);",
      "}",
    ].join("\n");

    const findings = ttl(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.line).toBe(5);
  });
});

/**
 * KNOWN LIMITATIONS. The rule is file-level and text-based: any real
 * `extend_ttl` anywhere in the file satisfies it, whatever storage type or
 * key it targets. These tests pin today's behavior so that tightening the
 * rule (per-storage-type or per-function matching) is a deliberate change
 * that updates them, rather than an accidental one.
 */
describe("AP-STORAGE-001 known limitations (documented current behavior)", () => {
  it("lets a temporary extend_ttl satisfy unextended persistent storage", () => {
    const code = `
      fn put(env: Env, k: Symbol, v: i128) {
        env.storage().persistent().set(&k, &v);
        env.storage().temporary().extend_ttl(&k, 10, 20);
      }
    `;

    expect(ttl(code)).toHaveLength(0);
  });

  it("lets an extend_ttl in another function satisfy the whole file", () => {
    const code = `
      fn save(env: Env, k: Symbol, v: i128) {
        env.storage().persistent().set(&k, &v);
      }
      fn unrelated(env: Env, k: Symbol) {
        env.storage().temporary().extend_ttl(&k, 10, 20);
      }
    `;

    expect(ttl(code)).toHaveLength(0);
  });

  it("treats extend_ttl text inside a string literal as a bump", () => {
    const code = `
      fn save(env: Env, k: Symbol, v: i128) {
        env.storage().persistent().set(&k, &v);
        let note = "remember to call .extend_ttl(";
      }
    `;

    expect(ttl(code)).toHaveLength(0);
  });
});