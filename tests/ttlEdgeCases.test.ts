import { describe, it, expect } from "vitest";
import fs from "fs";
import { fileURLToPath } from "url";
import MissingRequireAuthPlugin from "../src/plugins/missingRequireAuth";
import UnwrapUsagePlugin from "../src/plugins/unwrapUsage";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";

const edgeCases = fs.readFileSync(
  fileURLToPath(new URL("../contracts/TtlEdgeCases.rs", import.meta.url)),
  "utf-8",
);
const managed = fs.readFileSync(
  fileURLToPath(new URL("../contracts/TtlManaged.rs", import.meta.url)),
  "utf-8",
);

describe("TTL edge-case fixtures (temporary vs persistent storage)", () => {
  describe("TtlEdgeCases.rs (unmanaged TTL)", () => {
    it("flags persistent and temporary storage written without extend_ttl", () => {
      const vulns = MissingExtendTtlPlugin.scan(edgeCases);
      expect(vulns.length).toBeGreaterThan(0);
      expect(vulns[0]?.id).toBe("AP-STORAGE-001");
      expect(vulns[0]?.severity).toBe("high");
      expect(vulns[0]?.remediation).toContain("extend_ttl");
    });

    it("flags every function doing auth-sensitive writes without require_auth", () => {
      const vulns = MissingRequireAuthPlugin.scan(edgeCases);
      const names = vulns.map((v) => v.location.function);
      expect(names).toEqual(
        expect.arrayContaining([
          "set_balance",
          "grant_session_allowance",
          "spend_session_allowance",
          "flush",
        ]),
      );
      // get_balance only reads storage; it must not be auth-flagged.
      expect(names).not.toContain("get_balance");
      for (const v of vulns) {
        expect(v.id).toBe("AP-AUTH-001");
        expect(v.severity).toBe("critical");
      }
    });

    it("flags .unwrap() on a possibly-expired persistent read", () => {
      const vulns = UnwrapUsagePlugin.scan(edgeCases);
      expect(vulns.length).toBe(1);
      expect(vulns[0]?.id).toBe("AP-ERROR-001");
      expect(vulns[0]?.message).toContain(".unwrap()");
    });
  });

  describe("TtlManaged.rs (TTL managed)", () => {
    it("reports no findings on the managed fixture", () => {
      expect(MissingRequireAuthPlugin.scan(managed).length).toBe(0);
      expect(UnwrapUsagePlugin.scan(managed).length).toBe(0);
      expect(MissingExtendTtlPlugin.scan(managed).length).toBe(0);
    });
  });
});
