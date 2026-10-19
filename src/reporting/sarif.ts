import { createHash } from "crypto";
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
  /** Optional per-rule help URIs, defaulting to README anchors. */
  ruleHelpUris?: Map<string, string>;
  /** Optional driver information URI override. */
  informationUri?: string;
  /** Optional automationDetails id override. */
  automationId?: string;
}

const SEVERITY_TO_SARIF_LEVEL: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

/**
 * Computes a deterministic partial fingerprint (primaryLocationLineHash)
 * for a finding from its normalized file path, rule id, and finding message.
 */
export function computeLineHash(finding: FileFinding): string {
  const normFile = finding.file.replace(/\\/g, "/");
  return createHash("sha256")
    .update(`${normFile}:${finding.id}:${finding.message}`)
    .digest("hex");
}

export function toSarifLog(
  report: ScanReport,
  options: SarifOptions,
): Record<string, unknown> {
  const infoUri =
    options.informationUri ?? "https://github.com/Emmanuel-Ugochukwu1/auditpulse-core";

  // Compute highest confidence per rule id seen in this report
  const confidenceOrder: Record<string, number> = { high: 3, medium: 2, low: 1 };
  const bestConfidenceByRule = new Map<string, "high" | "medium" | "low">();
  for (const finding of report.findings) {
    if (finding.confidence) {
      const current = bestConfidenceByRule.get(finding.id);
      if (!current || (confidenceOrder[finding.confidence] ?? 0) > (confidenceOrder[current] ?? 0)) {
        bestConfidenceByRule.set(finding.id, finding.confidence);
      }
    }
  }

  // One rule entry per finding id, in first-seen order.
  const rulesById = new Map<
    string,
    {
      id: string;
      shortDescription: { text: string };
      helpUri: string;
      defaultConfiguration: { level: string };
      properties: { tags: string[]; precision: string };
    }
  >();
  for (const finding of report.findings) {
    if (rulesById.has(finding.id)) continue;
    const rulePrecision = bestConfidenceByRule.get(finding.id) ?? "high";
    rulesById.set(finding.id, {
      id: finding.id,
      shortDescription: {
        text: options.ruleDescriptions.get(finding.id) ?? finding.id,
      },
      helpUri: options.ruleHelpUris?.get(finding.id) ?? `${infoUri}#${finding.id.toLowerCase()}`,
      defaultConfiguration: {
        level: SEVERITY_TO_SARIF_LEVEL[finding.severity] ?? "warning",
      },
      properties: {
        tags: ["security", "soroban"],
        precision: rulePrecision,
      },
    });
  }
  const rules = [...rulesById.values()];

  const results = report.findings.map((finding) => {
    const props: Record<string, unknown> = {};
    if (finding.remediation !== undefined) {
      props.remediation = finding.remediation;
    }
    if (finding.confidence !== undefined) {
      props.precision = finding.confidence;
    }

    return {
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
        primaryLocationLineHash: computeLineHash(finding),
      },
      ...(Object.keys(props).length > 0 ? { properties: props } : {}),
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: infoUri,
            rules,
          },
        },
        automationDetails: {
          id: options.automationId ?? `${TOOL_NAME}/${TOOL_VERSION}`,
          description: {
            text: `${TOOL_NAME} v${TOOL_VERSION} scan execution`,
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
