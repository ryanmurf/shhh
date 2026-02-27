import type { Finding } from "./types.js";

/**
 * Context type indicating where in the conversation a secret appeared.
 */
export type ContextType =
  | "user_input"
  | "ai_output"
  | "tool_result"
  | "config"
  | "unknown";

/**
 * A Finding enriched with severity scoring data.
 */
export interface ScoredFinding extends Finding {
  /** Numeric risk score from 0-100 (higher = more dangerous) */
  score: number;
  /** Where in the conversation or configuration the secret appeared */
  contextType: ContextType;
  /** Human-readable reasons contributing to the score */
  riskFactors: string[];
}

/**
 * Base score mapping from severity level.
 */
const SEVERITY_BASE_SCORES: Record<string, number> = {
  critical: 80,
  high: 60,
  medium: 40,
  low: 20,
};

/**
 * Known test/example patterns that reduce the score significantly.
 */
const TEST_PATTERNS = [
  /EXAMPLE/i,
  /test[_-]?key/i,
  /sample[_-]?key/i,
  /fake[_-]?key/i,
  /dummy/i,
  /placeholder/i,
  /your[_-]?api/i,
  /change[_-]?me/i,
  /replace[_-]?me/i,
  /TODO/,
  /xxxx/i,
];

/**
 * Cloud credential type keywords that increase the score.
 */
const CLOUD_CREDENTIAL_PATTERNS = [
  /aws/i,
  /github/i,
];

/**
 * Keywords in file paths that indicate a config file context.
 */
const CONFIG_PATH_PATTERNS = [
  "config",
  "settings",
  ".mcp",
  "plugin",
];

/**
 * Keywords in file paths that indicate an archived/old session.
 */
const ARCHIVE_PATH_PATTERNS = [
  "archive",
  "archived",
  "old",
  "backup",
  "deprecated",
];

/**
 * Detect the context type from line content and file path.
 */
function detectContextType(lineContent: string, filePath: string): ContextType {
  // Check line content patterns first
  if (
    lineContent.includes('"role":"user"') ||
    lineContent.includes('"role": "user"')
  ) {
    return "user_input";
  }

  if (
    lineContent.includes('"role":"assistant"') ||
    lineContent.includes('"role": "assistant"')
  ) {
    return "ai_output";
  }

  if (
    lineContent.includes('"type":"tool_result"') ||
    lineContent.includes('"type": "tool_result"') ||
    lineContent.includes('"tool_use"')
  ) {
    return "tool_result";
  }

  // Check file path for config indicators
  const lowerPath = filePath.toLowerCase();
  if (CONFIG_PATH_PATTERNS.some((pattern) => lowerPath.includes(pattern))) {
    return "config";
  }

  return "unknown";
}

/**
 * Get the score adjustment for a given context type.
 */
function contextScoreAdjustment(contextType: ContextType): number {
  switch (contextType) {
    case "user_input":
      return 15;
    case "ai_output":
      return 5;
    case "tool_result":
      return 10;
    case "config":
      return 20;
    case "unknown":
      return 0;
  }
}

/**
 * Check if a secret type matches known cloud credential patterns.
 */
function isCloudCredential(secretType: string): boolean {
  return CLOUD_CREDENTIAL_PATTERNS.some((pattern) => pattern.test(secretType));
}

/**
 * Check if a file path appears to be an archived/old session.
 */
function isArchivedSession(filePath: string): boolean {
  const lowerPath = filePath.toLowerCase();
  return ARCHIVE_PATH_PATTERNS.some((pattern) => lowerPath.includes(pattern));
}

/**
 * Check if a secret value (from redacted match or context) looks like test data.
 */
function isLikelyTestData(lineContent: string): boolean {
  return TEST_PATTERNS.some((pattern) => pattern.test(lineContent));
}

/**
 * Score a single finding based on its severity, context, and risk factors.
 *
 * @param finding - The finding to score
 * @param lineContent - The full content of the line where the secret was found
 * @returns A ScoredFinding with score, contextType, and riskFactors
 */
export function scoreFinding(
  finding: Finding,
  lineContent: string,
): ScoredFinding {
  const riskFactors: string[] = [];
  let score = SEVERITY_BASE_SCORES[finding.severity] ?? 20;

  // Context type detection and adjustment
  const contextType = detectContextType(lineContent, finding.filePath);
  const contextAdj = contextScoreAdjustment(contextType);
  if (contextAdj !== 0) {
    score += contextAdj;
    riskFactors.push(
      contextType === "user_input"
        ? "User directly typed secret"
        : contextType === "ai_output"
          ? "AI echoed secret back"
          : contextType === "tool_result"
            ? "Tool exposed secret"
            : "Secret in config file",
    );
  }

  // Cloud credential bonus
  if (isCloudCredential(finding.secretType)) {
    score += 5;
    riskFactors.push("Cloud credential");
  }

  // Archived session discount
  if (isArchivedSession(finding.filePath)) {
    score -= 10;
    riskFactors.push("Archived session");
  }

  // Test/example data discount
  if (isLikelyTestData(lineContent)) {
    score -= 20;
    riskFactors.push("Likely test data");
  }

  // Clamp score to 0-100
  score = Math.max(0, Math.min(100, score));

  return {
    ...finding,
    score,
    contextType,
    riskFactors,
  };
}

/**
 * Batch-score findings with deduplication analysis.
 *
 * Counts how many times each secret appears across all findings (by redacted
 * match value) and applies a repetition bonus: +5 per additional occurrence,
 * capped at +15.
 *
 * @param findings - Array of findings to score
 * @param getLineContent - Function to retrieve the content of a specific line
 * @returns Array of ScoredFindings with scores, context types, and risk factors
 */
export function scoreFindings(
  findings: Finding[],
  getLineContent: (filePath: string, line: number) => string,
): ScoredFinding[] {
  // Count occurrences of each redacted match value
  const matchCounts = new Map<string, number>();
  for (const finding of findings) {
    const key = finding.match;
    matchCounts.set(key, (matchCounts.get(key) ?? 0) + 1);
  }

  return findings.map((finding) => {
    const lineContent = getLineContent(finding.filePath, finding.line);
    const scored = scoreFinding(finding, lineContent);

    // Repetition bonus
    const count = matchCounts.get(finding.match) ?? 1;
    if (count > 1) {
      const repetitionBonus = Math.min((count - 1) * 5, 15);
      scored.score = Math.min(100, scored.score + repetitionBonus);
      scored.riskFactors.push(`Secret repeated ${count} times`);
    }

    return scored;
  });
}
