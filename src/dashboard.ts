import chalk from "chalk";
import type { Finding, Platform, ScanResult, Severity } from "./types.js";

/**
 * Severity display configuration: chalk color function and label.
 */
const SEVERITY_CONFIG: Record<
  Severity,
  { color: (text: string) => string; label: string }
> = {
  critical: { color: chalk.red, label: "Critical" },
  high: { color: chalk.yellow, label: "High" },
  medium: { color: chalk.cyan, label: "Medium" },
  low: { color: chalk.gray, label: "Low" },
};

/**
 * Unicode block characters used to render horizontal bar charts.
 * The array is indexed by eighths (0 = empty, 8 = full block).
 */
const BLOCK_CHARS = [" ", "\u258F", "\u258E", "\u258D", "\u258C", "\u258B", "\u258A", "\u2589", "\u2588"];

/**
 * Format a number with thousands separators (e.g., 1885 -> "1,885").
 */
function formatNumber(n: number): string {
  return n.toLocaleString("en-US");
}

/**
 * Build a horizontal bar of a given fractional width using unicode block characters.
 *
 * @param fraction - Value between 0 and 1 representing the proportion of maxWidth to fill
 * @param maxWidth - Maximum number of character columns the bar can occupy
 * @returns A string of block characters representing the bar
 */
function buildBar(fraction: number, maxWidth: number): string {
  if (fraction <= 0 || maxWidth <= 0) return "";

  const totalEighths = Math.round(fraction * maxWidth * 8);
  const fullBlocks = Math.floor(totalEighths / 8);
  const remainder = totalEighths % 8;

  let bar = BLOCK_CHARS[8].repeat(fullBlocks);
  if (remainder > 0) {
    bar += BLOCK_CHARS[remainder];
  }

  return bar;
}

/**
 * Pad or truncate a string to exactly `width` characters (left-aligned).
 */
function padRight(str: string, width: number): string {
  if (str.length >= width) return str.slice(0, width);
  return str + " ".repeat(width - str.length);
}

/**
 * Pad a string to `width` characters (right-aligned).
 */
function padLeft(str: string, width: number): string {
  if (str.length >= width) return str.slice(0, width);
  return " ".repeat(width - str.length) + str;
}

/**
 * Count findings by severity level.
 */
function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const f of findings) {
    counts[f.severity]++;
  }
  return counts;
}

/**
 * Count findings by platform.
 */
function countByPlatform(findings: Finding[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const f of findings) {
    counts.set(f.platform, (counts.get(f.platform) ?? 0) + 1);
  }
  return counts;
}

/**
 * Get the top N secret types sorted by count descending.
 */
function topSecretTypes(findings: Finding[], n: number): Array<{ name: string; count: number }> {
  const counts = new Map<string, number>();
  for (const f of findings) {
    counts.set(f.secretType, (counts.get(f.secretType) ?? 0) + 1);
  }

  return Array.from(counts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}

/**
 * Render a rich terminal dashboard summarizing scan results.
 *
 * Uses chalk for colors and unicode box-drawing / block characters for layout.
 * The output is a static, well-formatted summary screen suitable for printing
 * to stdout.
 *
 * @param result - The scan result to render
 * @returns A string containing the complete dashboard output
 */
export function renderDashboard(result: ScanResult): string {
  const termWidth = process.stdout.columns || 80;
  // Inner width is total minus the two border columns ("║" on each side)
  const innerWidth = termWidth - 4;

  // Box-drawing helpers
  const topBorder = "\u2554" + "\u2550".repeat(termWidth - 2) + "\u2557";
  const bottomBorder = "\u255A" + "\u2550".repeat(termWidth - 2) + "\u255D";
  const divider = "\u2560" + "\u2550".repeat(termWidth - 2) + "\u2563";

  function boxLine(content: string): string {
    // Strip ANSI codes for length calculation
    const stripped = content.replace(/\x1b\[[0-9;]*m/g, "");
    const padding = innerWidth - stripped.length;
    if (padding < 0) {
      return "\u2551 " + content + " \u2551";
    }
    return "\u2551 " + content + " ".repeat(padding) + " \u2551";
  }

  function centeredBoxLine(content: string): string {
    const stripped = content.replace(/\x1b\[[0-9;]*m/g, "");
    const totalPad = innerWidth - stripped.length;
    if (totalPad < 0) {
      return "\u2551 " + content + " \u2551";
    }
    const leftPad = Math.floor(totalPad / 2);
    const rightPad = totalPad - leftPad;
    return "\u2551 " + " ".repeat(leftPad) + content + " ".repeat(rightPad) + " \u2551";
  }

  const lines: string[] = [];

  // === Title ===
  lines.push(topBorder);
  lines.push(centeredBoxLine(chalk.bold.white("shhh \u2014 Scan Dashboard")));
  lines.push(divider);

  // === Scan metadata ===
  const durationSec = (result.scanDurationMs / 1000).toFixed(1);
  const platforms = result.platformsScanned.join(", ") || "none";
  lines.push(
    boxLine(
      `Files Scanned: ${chalk.bold(formatNumber(result.filesScanned))}    Duration: ${chalk.bold(durationSec + "s")}`,
    ),
  );
  lines.push(
    boxLine(`Platforms: ${chalk.cyan(platforms)}`),
  );
  lines.push(divider);

  // === Findings summary ===
  const severityCounts = countBySeverity(result.findings);
  lines.push(boxLine(chalk.bold("FINDINGS SUMMARY")));

  if (result.findings.length === 0) {
    lines.push(boxLine(chalk.green("No secrets found. All clear!")));
  } else {
    // Determine the max count for bar scaling
    const maxSevCount = Math.max(
      severityCounts.critical,
      severityCounts.high,
      severityCounts.medium,
      severityCounts.low,
      1,
    );

    // Layout: "  * Label:  count  bar"
    // Label column: 10 chars, count column: 8 chars, prefix: 4, gaps: ~6
    const barMaxWidth = Math.max(innerWidth - 30, 10);

    const severityOrder: Severity[] = ["critical", "high", "medium", "low"];
    for (const sev of severityOrder) {
      const count = severityCounts[sev];
      const config = SEVERITY_CONFIG[sev];
      const countStr = padLeft(formatNumber(count), 7);
      const fraction = count / maxSevCount;
      const bar = buildBar(fraction, barMaxWidth);
      lines.push(
        boxLine(
          `  ${config.color("\u25CF")} ${padRight(config.label + ":", 10)} ${countStr}  ${config.color(bar)}`,
        ),
      );
    }
  }

  lines.push(divider);

  // === Top secret types ===
  lines.push(boxLine(chalk.bold("TOP SECRET TYPES")));

  const topTypes = topSecretTypes(result.findings, 5);
  if (topTypes.length === 0) {
    lines.push(boxLine(chalk.dim("  (none)")));
  } else {
    // Find the longest type name for alignment
    const maxNameLen = Math.min(
      Math.max(...topTypes.map((t) => t.name.length)),
      innerWidth - 15,
    );

    for (let i = 0; i < topTypes.length; i++) {
      const entry = topTypes[i];
      const rank = `${i + 1}.`;
      const name = padRight(entry.name, maxNameLen);
      const countStr = padLeft(formatNumber(entry.count), 7);
      lines.push(boxLine(`  ${padRight(rank, 3)} ${name} ${countStr}`));
    }
  }

  lines.push(divider);

  // === Platform breakdown ===
  lines.push(boxLine(chalk.bold("PLATFORM BREAKDOWN")));

  const platformCounts = countByPlatform(result.findings);
  // Also include platforms that were scanned but had 0 findings
  for (const p of result.platformsScanned) {
    if (!platformCounts.has(p)) {
      platformCounts.set(p, 0);
    }
  }

  if (platformCounts.size === 0) {
    lines.push(boxLine(chalk.dim("  (none)")));
  } else {
    const maxPlatCount = Math.max(...platformCounts.values(), 1);
    // Sort platforms by count descending
    const sortedPlatforms = Array.from(platformCounts.entries()).sort(
      (a, b) => b[1] - a[1],
    );

    // Layout: "  name  bar  count"
    const platformNameWidth = Math.max(
      ...sortedPlatforms.map(([name]) => name.length),
      8,
    );
    const countColWidth = 8;
    const barMaxWidth = Math.max(innerWidth - platformNameWidth - countColWidth - 6, 10);

    for (const [name, count] of sortedPlatforms) {
      const fraction = count / maxPlatCount;
      const bar = buildBar(fraction, barMaxWidth);
      const countStr = padLeft(formatNumber(count), countColWidth);
      lines.push(
        boxLine(
          `  ${chalk.bold(padRight(name, platformNameWidth))} ${chalk.green(bar)}${countStr}`,
        ),
      );
    }
  }

  lines.push(bottomBorder);

  return lines.join("\n");
}
