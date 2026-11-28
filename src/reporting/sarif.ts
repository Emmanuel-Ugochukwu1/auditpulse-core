import { createHash } from "node:crypto";
import type { FileFinding, ScanReport } from "../scanner";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";

/**
 * SARIF 2.1.0 output for GitHub Code Scanning integration.
 *
 * Generation is kept separate from scanning: this module only shapes
 * ScanReport data into the SARIF format. Rules referenced in results are
 * derived from the engine-provided finding ids and the rule descriptions
 * supplied by the caller.
 */

export interface SarifOptions {
  /** id -> description, taken from the rule registry at scan time. */
  ruleDescriptions: Map<string, string>;
  /**
   * Optional id -> help URI overrides. Rules without an override get a
   * default help URI pointing at the README anchor derived from the rule
   * id, so no external documentation URL is ever fabricated.
   */
  ruleHelpUris?: Map<string, string>;
}

const REPO_README_URL =
  "https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/blob/main/README.md";

function defaultHelpUri(ruleId: string): string {
  return `${REPO_README_URL}#${ruleId.toLowerCase()}`;
}

/**
 * Stable fingerprint for a result, computed from the artifact URI, rule id
 * and message only — deliberately not the line number, so the fingerprint
 * survives code shifting lines between runs and GitHub Code Scanning does
 * not churn duplicate alerts.
 */
function primaryLocationLineHash(finding: FileFinding): string {
  const uri = finding.file.replace(/\\/g, "/");
  return createHash("sha256")
    .update(`${uri}\n${finding.id}\n${finding.message}`)
    .digest("hex");
}

const SEVERITY_TO_SARIF_LEVEL: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

export function toSarifLog(
  report: ScanReport,
  options: SarifOptions,
): Record<string, unknown> {
  // One rule entry per finding id, in first-seen order.
  const rulesById = new Map<
    string,
    {
      id: string;
      shortDescription: { text: string };
      helpUri: string;
      precision?: string;
      defaultConfiguration: { level: string };
      properties: { tags: string[] };
    }
  >();
  for (const finding of report.findings) {
    const existing = rulesById.get(finding.id);
    if (existing) {
      // Precision comes from the finding model's confidence; the first
      // finding that carries one wins so output stays deterministic.
      if (existing.precision === undefined && finding.confidence !== undefined) {
        existing.precision = finding.confidence;
      }
      continue;
    }
    rulesById.set(finding.id, {
      id: finding.id,
      shortDescription: {
        text: options.ruleDescriptions.get(finding.id) ?? finding.id,
      },
      helpUri: options.ruleHelpUris?.get(finding.id) ?? defaultHelpUri(finding.id),
      ...(finding.confidence !== undefined
        ? { precision: finding.confidence }
        : {}),
      defaultConfiguration: {
        level: SEVERITY_TO_SARIF_LEVEL[finding.severity] ?? "warning",
      },
      properties: { tags: ["security", "soroban"] },
    });
  }
  const rules = [...rulesById.values()];

  const results = report.findings.map((finding) => ({
    ruleId: finding.id,
    level: SEVERITY_TO_SARIF_LEVEL[finding.severity] ?? "warning",
    message: { text: finding.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.file.replace(/\\/g, "/") },
          region: {
            startLine: finding.location.line,
            ...(finding.location.column !== undefined
              ? { startColumn: finding.location.column }
              : {}),
          },
        },
      },
    ],
    partialFingerprints: {
      primaryLocationLineHash: primaryLocationLineHash(finding),
    },
    ...(finding.remediation !== undefined
      ? { properties: { remediation: finding.remediation } }
      : {}),
  }));

  return {
    $schema:
      "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        automationDetails: {
          id: `${TOOL_NAME}/${TOOL_VERSION}`,
          description: {
            text: `${TOOL_NAME} ${TOOL_VERSION} scan run`,
          },
        },
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: "https://github.com/Emmanuel-Ugochukwu1/auditpulse-core",
            rules,
          },
        },
        results,
      },
    ],
  };
}

export function renderSarif(
  report: ScanReport,
  options: SarifOptions,
): string {
  return `${JSON.stringify(toSarifLog(report, options), null, 2)}\n`;
}
