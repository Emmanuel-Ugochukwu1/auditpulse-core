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
  /** Optional id -> documentation URI. Defaults to the README checks section. */
  ruleHelpUris?: ReadonlyMap<string, string>;
}

const DEFAULT_HELP_URI =
  "https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/blob/main/README.md#checks";
const SARIF_TAGS = ["security", "soroban", "smart-contracts"];

const SEVERITY_TO_SARIF_LEVEL: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

/**
 * Builds a deterministic fingerprint that is stable when a finding moves to a
 * different line. `occurrence` distinguishes otherwise identical findings in
 * the same function without introducing line/column coupling.
 */
export function findingFingerprint(
  finding: FileFinding,
  occurrence = 0,
): string {
  const normalizedFile = finding.file.replace(/\\/g, "/");
  const identity = [
    normalizedFile,
    finding.id,
    finding.location.function ?? "",
    finding.message,
    String(occurrence),
  ].join("\0");
  return createHash("sha256").update(identity).digest("hex");
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
      properties: { tags: string[] };
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
      helpUri: options.ruleHelpUris?.get(finding.id) ?? DEFAULT_HELP_URI,
      properties: { tags: SARIF_TAGS },
    });
  }
  const rules = [...rulesById.values()];

  const occurrenceByFingerprintBase = new Map<string, number>();
  const results = report.findings.map((finding) => {
    const normalizedFile = finding.file.replace(/\\/g, "/");
    const fingerprintBase = [
      normalizedFile,
      finding.id,
      finding.location.function ?? "",
      finding.message,
    ].join("\0");
    const occurrence = occurrenceByFingerprintBase.get(fingerprintBase) ?? 0;
    occurrenceByFingerprintBase.set(fingerprintBase, occurrence + 1);

    const properties: Record<string, string> = {};
    if (finding.confidence !== undefined) {
      properties.precision = finding.confidence;
    }
    if (finding.remediation !== undefined) {
      properties.remediation = finding.remediation;
    }

    return {
      ruleId: finding.id,
      level: SEVERITY_TO_SARIF_LEVEL[finding.severity] ?? "warning",
      message: { text: finding.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: normalizedFile },
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
        primaryLocationLineHash: findingFingerprint(finding, occurrence),
      },
      ...(Object.keys(properties).length > 0 ? { properties } : {}),
    };
  });

  return {
    $schema:
      "https://json.schemastore.org/sarif-2.1.0.json",
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
          id: `${TOOL_NAME}/${TOOL_VERSION}`,
          description: { text: `${TOOL_NAME} static analysis run` },
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
