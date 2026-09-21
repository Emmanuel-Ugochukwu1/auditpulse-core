import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";

describe("TTL and Storage Expirations Edge-Case Fixture", () => {
  it("flags missing TTL and unwrap usage on TtlStorageTiers.rs contract", () => {
    const filePath = path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      "..",
      "contracts",
      "TtlStorageTiers.rs",
    );
    const code = fs.readFileSync(filePath, "utf-8");
    const engine = new AuditEngine(createDefaultRegistry());
    const findings = engine.run(code);

    const storageFindings = findings.filter((f) => f.id === "AP-STORAGE-001");
    expect(storageFindings.length).toBeGreaterThan(0);
  });
});
