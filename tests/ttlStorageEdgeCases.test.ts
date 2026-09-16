import { describe, expect, it } from "vitest";
import fs from "fs";
import { fileURLToPath } from "url";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import UnwrapUsagePlugin from "../src/plugins/unwrapUsage";

const fixture = fs.readFileSync(
  fileURLToPath(new URL("../contracts/TtlStorageEdgeCases.rs", import.meta.url)),
  "utf-8",
);

describe("TTL/storage-expiry bounty fixture", () => {
  it("detects storage that is never kept alive", () => {
    const findings = MissingExtendTtlPlugin.scan(fixture);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-STORAGE-001");
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.remediation).toContain("extend_ttl");
  });

  it("proves the expired-read panic edge case", () => {
    const findings = UnwrapUsagePlugin.scan(fixture);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-ERROR-001");
    expect(findings[0]?.message).toContain(".unwrap()");
  });
});
