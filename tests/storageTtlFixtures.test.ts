import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { AuditEngine } from "../src/engine";
import { RuleRegistry } from "../src/registry";
import { MissingExtendTtlPlugin } from "../src/plugins/missingExtendTtl";

const fixtures = ["TemporaryTtlEdgeCases.rs", "PersistentTtlEdgeCases.rs"];

// This rule is intentionally file-level. An extension in a conditional
// branch suppresses its finding; that does not prove every runtime path
// refreshes the entry or that a particular ledger TTL is valid.
const scanners = [
  {
    name: "source-text rule",
    scan: (code: string) => new MissingExtendTtlPlugin().scan(code),
  },
  {
    name: "engine integration",
    scan: (code: string) =>
      new AuditEngine(
        new RuleRegistry().register(new MissingExtendTtlPlugin()),
      ).run(code),
  },
];

describe.each(scanners)("storage TTL fixtures: $name", ({ scan }) => {
  describe.each(fixtures)("%s", (fixture) => {
    const source = readFileSync(
      new URL(`../contracts/${fixture}`, import.meta.url),
      "utf8",
    );
    const extension = "storage.extend_ttl(&key, 1, 2);";

    it("recognizes a storage alias extended behind a runtime guard", () => {
      expect(scan(source)).toEqual([]);
    });

    it("reports storage access when the extension is removed", () => {
      const withoutExtension = source.replace(extension, "");
      expect(withoutExtension).not.toBe(source);

      expect(scan(withoutExtension)).toEqual([
        expect.objectContaining({
          id: "AP-STORAGE-001",
          severity: "high",
          confidence: "medium",
        }),
      ]);
    });

    it("does not mistake a commented-out extension for a live call", () => {
      const commentedExtension = source.replace(extension, `// ${extension}`);
      expect(commentedExtension).not.toBe(source);

      expect(scan(commentedExtension)).toEqual([
        expect.objectContaining({ id: "AP-STORAGE-001" }),
      ]);
    });
  });
});
