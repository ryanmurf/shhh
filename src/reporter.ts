import chalk from "chalk";
import type { Finding, ScanResult, Severity } from "./types.js";
import type { ScoredFinding } from "./scoring.js";
import { renderDashboard } from "./dashboard.js";

/**
 * Map severity levels to chalk color functions and display labels.
 */
const SEVERITY_STYLES: Record<
  Severity,
  { color: (text: string) => string; label: string }
> = {
  critical: { color: chalk.bgRed.white.bold, label: " CRITICAL " },
  high: { color: chalk.red.bold, label: "HIGH" },
  medium: { color: chalk.yellow.bold, label: "MEDIUM" },
  low: { color: chalk.blue, label: "LOW" },
};

/**
 * Type guard: check if a Finding is actually a ScoredFinding.
 */
function isScoredFinding(finding: Finding): finding is ScoredFinding {
  return "score" in finding && "contextType" in finding && "riskFactors" in finding;
}

/**
 * Sort findings by severity (most severe first), then by file path.
 */
function sortFindings(findings: Finding[]): Finding[] {
  const order: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  return [...findings].sort((a, b) => {
    const severityDiff = order[a.severity] - order[b.severity];
    if (severityDiff !== 0) return severityDiff;
    return a.filePath.localeCompare(b.filePath);
  });
}

/**
 * Format scan results as colorized text for terminal output.
 *
 * @param result - The scan result to format
 * @returns A formatted string suitable for console output
 */
export function formatText(result: ScanResult): string {
  const lines: string[] = [];

  lines.push("");
  lines.push(chalk.bold.underline("shhh - Secret Scanner Results"));
  lines.push("");

  // Summary
  lines.push(
    chalk.dim(`Scanned ${result.filesScanned} files across platforms: `) +
      chalk.cyan(result.platformsScanned.join(", ") || "none") +
      chalk.dim(` in ${result.scanDurationMs}ms`),
  );
  lines.push("");

  if (result.findings.length === 0) {
    lines.push(chalk.green.bold("No secrets found. All clear!"));
    lines.push("");
    return lines.join("\n");
  }

  // Count by severity
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const f of result.findings) {
    counts[f.severity]++;
  }

  lines.push(chalk.bold("Summary:"));
  if (counts.critical > 0)
    lines.push(
      `  ${SEVERITY_STYLES.critical.color(SEVERITY_STYLES.critical.label)} ${counts.critical} finding(s)`,
    );
  if (counts.high > 0)
    lines.push(
      `  ${SEVERITY_STYLES.high.color(SEVERITY_STYLES.high.label)}     ${counts.high} finding(s)`,
    );
  if (counts.medium > 0)
    lines.push(
      `  ${SEVERITY_STYLES.medium.color(SEVERITY_STYLES.medium.label)}   ${counts.medium} finding(s)`,
    );
  if (counts.low > 0)
    lines.push(
      `  ${SEVERITY_STYLES.low.color(SEVERITY_STYLES.low.label)}      ${counts.low} finding(s)`,
    );
  lines.push("");

  // Detailed findings
  lines.push(chalk.bold("Findings:"));
  lines.push(chalk.dim("-".repeat(72)));

  const sorted = sortFindings(result.findings);

  for (const finding of sorted) {
    const style = SEVERITY_STYLES[finding.severity];

    lines.push(
      `  ${style.color(style.label)} ${chalk.white.bold(finding.secretType)}`,
    );
    lines.push(
      `  ${chalk.dim("File:")}     ${finding.filePath}:${finding.line}:${finding.column}`,
    );
    lines.push(
      `  ${chalk.dim("Platform:")} ${finding.platform}`,
    );
    lines.push(
      `  ${chalk.dim("Match:")}    ${chalk.yellow(finding.match)}`,
    );
    lines.push(
      `  ${chalk.dim("Context:")}  ${finding.context}`,
    );

    if (isScoredFinding(finding)) {
      lines.push(
        `  ${chalk.dim("Score:")}    ${chalk.bold(String(finding.score))} / 100  ${chalk.dim("Context type:")} ${finding.contextType}`,
      );
      if (finding.riskFactors.length > 0) {
        lines.push(
          `  ${chalk.dim("Risk:")}     ${finding.riskFactors.join(", ")}`,
        );
      }
    }

    lines.push(chalk.dim("-".repeat(72)));
  }

  lines.push("");
  lines.push(
    chalk.bold.red(`Total: ${result.findings.length} secret(s) found.`),
  );
  lines.push("");

  return lines.join("\n");
}

/**
 * Format scan results as JSON.
 *
 * When findings are ScoredFindings, the score, contextType, and riskFactors
 * fields are included automatically since JSON.stringify serialises all
 * enumerable properties.
 *
 * @param result - The scan result to format
 * @returns A JSON string
 */
export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

/**
 * Format scan results as SARIF (Static Analysis Results Interchange Format).
 * This is a stub for future implementation.
 *
 * @param result - The scan result to format
 * @returns A SARIF JSON string
 */
export function formatSarif(result: ScanResult): string {
  const sarif = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "shhh",
            version: "0.1.1",
            informationUri: "https://github.com/shhh-scanner/shhh",
            rules: [],
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.secretType.toLowerCase().replace(/\s+/g, "-"),
          level:
            f.severity === "critical" || f.severity === "high"
              ? "error"
              : f.severity === "medium"
                ? "warning"
                : "note",
          message: {
            text: `${f.secretType} detected`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.filePath,
                },
                region: {
                  startLine: f.line,
                  startColumn: f.column,
                },
              },
            },
          ],
          properties: {
            platform: f.platform,
            severity: f.severity,
          },
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

/**
 * Format scan results as a rich terminal dashboard.
 *
 * Renders a box-drawn summary screen with severity bar charts,
 * top secret types, and platform breakdown.
 *
 * @param result - The scan result to format
 * @returns A formatted dashboard string suitable for console output
 */
export function formatDashboard(result: ScanResult): string {
  return renderDashboard(result);
}
