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
  /** Optional rule help URIs (or defaults to README anchors derived from rule ids) */
  ruleHelpUris?: Map<string, string>;
}

const SEVERITY_TO_SARIF_LEVEL: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

export function computeLineHash(
  file: string,
  ruleId: string,
  message: string,
): string {
  return createHash("sha256")
    .update(`${file}:${ruleId}:${message}`)
    .digest("hex");
}

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
      defaultConfiguration: { level: string };
      helpUri: string;
      properties: {
        precision: string;
        tags: string[];
      };
    }
  >();
  for (const finding of report.findings) {
    if (rulesById.has(finding.id)) continue;
    rulesById.set(finding.id, {
      id: finding.id,
      shortDescription: {
        text: options.ruleDescriptions.get(finding.id) ?? finding.id,
      },
      defaultConfiguration: {
        level: SEVERITY_TO_SARIF_LEVEL[finding.severity] ?? "warning",
      },
      helpUri:
        options.ruleHelpUris?.get(finding.id) ??
        `https://github.com/Emmanuel-Ugochukwu1/auditpulse-core#${finding.id.toLowerCase()}`,
      properties: {
        precision: finding.confidence ?? "medium",
        tags: ["security", "soroban", "smart-contracts"],
      },
    });
  }
  const rules = [...rulesById.values()];

  const results = report.findings.map((finding) => {
    const normFile = finding.file.replace(/\\/g, "/");
    const props: Record<string, unknown> = {};
    if (finding.confidence !== undefined) {
      props.precision = finding.confidence;
    }
    if (finding.remediation !== undefined) {
      props.remediation = finding.remediation;
    }

    return {
      ruleId: finding.id,
      level: SEVERITY_TO_SARIF_LEVEL[finding.severity] ?? "warning",
      message: { text: finding.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: normFile },
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
        primaryLocationLineHash: computeLineHash(normFile, finding.id, finding.message),
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
            informationUri: "https://github.com/Emmanuel-Ugochukwu1/auditpulse-core",
            rules,
          },
        },
        automationDetails: {
          description: {
            text: `AuditPulse CLI scan ${TOOL_VERSION}`,
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
