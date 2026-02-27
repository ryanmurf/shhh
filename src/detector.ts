import { randomUUID } from "node:crypto";
import type { Finding, Platform, Severity } from "./types.js";
import { calculateEntropy } from "./entropy.js";

/**
 * A pattern definition for secret detection.
 */
export interface SecretPattern {
  name: string;
  severity: Severity;
  pattern: RegExp;
}

/**
 * All regex patterns used to detect secrets in file content.
 * Each pattern has a descriptive name, severity level, and a regex with global flag.
 */
const SECRET_PATTERNS: SecretPattern[] = [
  // AWS
  {
    name: "AWS Access Key ID",
    severity: "critical",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    name: "AWS Secret Access Key",
    severity: "critical",
    pattern: /\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/g,
  },

  // GitHub tokens
  {
    name: "GitHub Personal Access Token",
    severity: "high",
    pattern: /\bghp_[A-Za-z0-9]{36,}\b/g,
  },
  {
    name: "GitHub OAuth Token",
    severity: "high",
    pattern: /\bgho_[A-Za-z0-9]{36,}\b/g,
  },
  {
    name: "GitHub Server Token",
    severity: "high",
    pattern: /\bghs_[A-Za-z0-9]{36,}\b/g,
  },
  {
    name: "GitHub Refresh Token",
    severity: "high",
    pattern: /\bghr_[A-Za-z0-9]{36,}\b/g,
  },
  {
    name: "GitHub Fine-Grained PAT",
    severity: "high",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  },

  // Slack tokens
  {
    name: "Slack Bot Token",
    severity: "high",
    pattern: /\bxoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}\b/g,
  },
  {
    name: "Slack User Token",
    severity: "high",
    pattern: /\bxoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}\b/g,
  },
  {
    name: "Slack Secret Token",
    severity: "high",
    pattern: /\bxoxs-[0-9A-Za-z.+\-]{20,}\b/g,
  },

  // Generic API keys
  {
    name: "Generic API Key (assignment)",
    severity: "medium",
    pattern: /\b(?:api_key|apikey|api-key|API_KEY|APIKEY)\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,})["']?/gi,
  },

  // Private keys — require at least one line of base64 key body after the header
  // to avoid matching code that merely references the PEM header string.
  {
    name: "RSA Private Key",
    severity: "critical",
    pattern: /-----BEGIN RSA PRIVATE KEY-----[\s]*[A-Za-z0-9+/=]{20,}/g,
  },
  {
    name: "EC Private Key",
    severity: "critical",
    pattern: /-----BEGIN EC PRIVATE KEY-----[\s]*[A-Za-z0-9+/=]{20,}/g,
  },
  {
    name: "PGP Private Key",
    severity: "critical",
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s]*[A-Za-z0-9+/=]{20,}/g,
  },
  {
    name: "Generic Private Key",
    severity: "critical",
    pattern: /-----BEGIN PRIVATE KEY-----[\s]*[A-Za-z0-9+/=]{20,}/g,
  },

  // Database connection strings
  {
    name: "PostgreSQL Connection String",
    severity: "high",
    pattern: /postgres(?:ql)?:\/\/[^\s"'`<>{}|\\^]+@[^\s"'`<>{}|\\^]+/g,
  },
  {
    name: "MySQL Connection String",
    severity: "high",
    pattern: /mysql:\/\/[^\s"'`<>{}|\\^]+@[^\s"'`<>{}|\\^]+/g,
  },
  {
    name: "MongoDB Connection String",
    severity: "high",
    pattern: /mongodb(?:\+srv)?:\/\/[^\s"'`<>{}|\\^]+@[^\s"'`<>{}|\\^]+/g,
  },

  // JWTs
  {
    name: "JWT (JSON Web Token)",
    severity: "medium",
    pattern: /\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g,
  },

  // Bearer tokens
  {
    name: "Bearer Token",
    severity: "medium",
    pattern: /\bBearer\s+[A-Za-z0-9_\-.~+/]{20,}=*\b/g,
  },
];

/**
 * Minimum string length considered for high-entropy detection.
 */
const ENTROPY_MIN_LENGTH = 20;

/**
 * Maximum string length considered for high-entropy detection.
 * Real API keys/tokens are rarely longer than 100 characters.
 * Longer strings are almost certainly base64-encoded file content, not secrets.
 */
const ENTROPY_MAX_LENGTH = 100;

/**
 * Shannon entropy threshold above which a string is flagged.
 * Raised from 4.5 to 5.0 to reduce false positives on session data.
 */
const ENTROPY_THRESHOLD = 5.0;

/**
 * Maximum number of high-entropy findings per file.
 * If a file exceeds this cap, it's almost certainly all noise (e.g., session data).
 */
const ENTROPY_MAX_PER_FILE = 10;

/**
 * Regex to find candidate high-entropy strings.
 * Matches quoted strings and unquoted token-like strings of sufficient length.
 */
const ENTROPY_CANDIDATE_PATTERN =
  /["']([A-Za-z0-9+/=_\-]{20,})["']|(?:=|:\s*)([A-Za-z0-9+/=_\-]{20,})\b/g;

/**
 * Keywords in surrounding context that indicate a string is NOT a secret
 * but rather encoded content, message body, tool output, etc.
 */
const ENTROPY_CONTEXT_SKIP_KEYWORDS = [
  "content",
  "output",
  "message",
  "text",
  "body",
  "data",
  "result",
  "response",
  "base64",
  "encoded",
  "file_content",
  "source_code",
  "diff",
  "patch",
];

/**
 * JSON key names whose values should never be flagged as high-entropy secrets.
 * Matches patterns like "content": "...", "text": "...", etc.
 */
const JSON_SAFE_KEY_PATTERN =
  /["'](?:content|text|output|body|message|data)["']\s*:\s*["']/i;

/**
 * Line-level patterns that indicate conversation/message content (not config).
 * If a line matches any of these, skip entropy detection entirely.
 */
const CONVERSATION_LINE_PATTERNS = [
  '"role":"assistant"',
  '"type":"message"',
  '"type":"tool_result"',
];

/**
 * Common placeholder patterns that should not be flagged as secrets.
 */
const PLACEHOLDER_PATTERNS = [
  /^your[_-]/i,
  /^example/i,
  /^test[_-]/i,
  /^fake[_-]/i,
  /^dummy/i,
  /^sample/i,
  /^replace[_-]?me/i,
  /^todo$/i,
  /^change[_-]?me/i,
  /^insert[_-]/i,
  /^put[_-]/i,
  /here$/i,
];

/**
 * Determine whether a matched value is a likely false positive (placeholder or low-entropy).
 * Returns true if the value should be excluded from results.
 */
function isFalsePositive(value: string): boolean {
  // Check against known placeholder patterns
  for (const pattern of PLACEHOLDER_PATTERNS) {
    if (pattern.test(value)) {
      return true;
    }
  }

  // Check for repeated single character (e.g., "xxxxxxxxxxxx", "aaaaaaaaa")
  if (/^(.)\1+$/.test(value)) {
    return true;
  }

  return false;
}

/**
 * Redact a matched secret string, preserving only the first 4 and last 4 characters.
 */
function redact(value: string): string {
  if (value.length <= 12) {
    return value.slice(0, 3) + "***" + value.slice(-2);
  }
  return value.slice(0, 4) + "****" + value.slice(-4);
}

/**
 * Extract a short context window around a match position, with the secret redacted.
 */
function extractContext(
  content: string,
  matchStart: number,
  matchEnd: number,
  contextRadius: number = 40,
): string {
  const start = Math.max(0, matchStart - contextRadius);
  const end = Math.min(content.length, matchEnd + contextRadius);

  const before = content.slice(start, matchStart);
  const matched = content.slice(matchStart, matchEnd);
  const after = content.slice(matchEnd, end);

  const prefix = start > 0 ? "..." : "";
  const suffix = end < content.length ? "..." : "";

  const raw = prefix + before + redact(matched) + after + suffix;
  // Strip control characters (except space) that can break JSON serialization
  return raw.replace(/[\x00-\x1f\x7f]/g, (ch) => (ch === "\t" ? " " : ""));
}

/**
 * Compute the line and column for a character offset in the content.
 * Both are 1-based.
 */
function getPosition(
  content: string,
  offset: number,
): { line: number; column: number } {
  let line = 1;
  let lastNewline = -1;

  for (let i = 0; i < offset && i < content.length; i++) {
    if (content[i] === "\n") {
      line++;
      lastNewline = i;
    }
  }

  const column = offset - lastNewline;
  return { line, column };
}

/**
 * Detect secrets in the given file content.
 *
 * Runs all regex-based pattern checks and a high-entropy string check
 * against the content, returning an array of Finding objects.
 *
 * @param content - The full text content to scan
 * @param filePath - The file path (used for reporting, not read from disk)
 * @param platform - The platform this file belongs to
 * @param customRules - Optional array of additional SecretPattern objects to run alongside built-in patterns
 * @returns Array of Finding objects for each detected secret
 */
export function detectSecrets(
  content: string,
  filePath: string,
  platform: Platform = "claude",
  customRules?: SecretPattern[],
): Finding[] {
  const findings: Finding[] = [];
  const seenOffsets = new Set<string>();

  // Combine built-in patterns with any custom rules
  const allPatterns: SecretPattern[] = customRules
    ? [...SECRET_PATTERNS, ...customRules]
    : SECRET_PATTERNS;

  // Run each regex pattern against the content
  for (const { name, severity, pattern } of allPatterns) {
    // Reset the regex state since we use global flag
    pattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const matchedStr = match[1] ?? match[0];
      const matchStart = match.index;
      const matchEnd = match.index + match[0].length;

      // Skip false positives (placeholders, repeated chars, etc.)
      if (isFalsePositive(matchedStr)) {
        continue;
      }

      // Deduplicate findings at the same offset
      const offsetKey = `${matchStart}:${matchEnd}`;
      if (seenOffsets.has(offsetKey)) {
        continue;
      }
      seenOffsets.add(offsetKey);

      const { line, column } = getPosition(content, matchStart);

      findings.push({
        id: randomUUID(),
        secretType: name,
        severity,
        match: redact(matchedStr),
        filePath,
        line,
        column,
        platform,
        context: extractContext(content, matchStart, matchEnd),
      });
    }
  }

  // High-entropy string detection
  ENTROPY_CANDIDATE_PATTERN.lastIndex = 0;

  let entropyFindingCount = 0;
  let entropyMatch: RegExpExecArray | null;
  while ((entropyMatch = ENTROPY_CANDIDATE_PATTERN.exec(content)) !== null) {
    const candidate = entropyMatch[1] ?? entropyMatch[2];
    if (!candidate || candidate.length < ENTROPY_MIN_LENGTH) {
      continue;
    }

    // Cap candidate length — real secrets are rarely > 100 chars.
    // Longer strings are almost certainly base64-encoded file content.
    if (candidate.length > ENTROPY_MAX_LENGTH) {
      continue;
    }

    const entropy = calculateEntropy(candidate);
    if (entropy <= ENTROPY_THRESHOLD) {
      continue;
    }

    const matchStart = entropyMatch.index;
    const matchEnd = entropyMatch.index + entropyMatch[0].length;

    // Skip if we already flagged this region with a named pattern
    const offsetKey = `${matchStart}:${matchEnd}`;
    if (seenOffsets.has(offsetKey)) {
      continue;
    }

    // --- Context-aware filtering ---

    // Find the line containing this match for context checks
    const lineStart = content.lastIndexOf("\n", matchStart) + 1;
    const lineEnd = content.indexOf("\n", matchEnd);
    const line = content.slice(lineStart, lineEnd === -1 ? content.length : lineEnd);

    // Skip entropy detection entirely for lines that are clearly
    // JSON message/conversation content, not config files where secrets live.
    const isConversationLine = CONVERSATION_LINE_PATTERNS.some(
      (pattern) => line.includes(pattern),
    );
    if (isConversationLine) {
      continue;
    }

    // Skip if surrounding context contains keywords suggesting non-secret content
    // (e.g., "content", "output", "message", "base64", "file_content", etc.)
    const contextWindow = content.slice(
      Math.max(0, matchStart - 100),
      Math.min(content.length, matchEnd + 50),
    ).toLowerCase();

    const isContentContext = ENTROPY_CONTEXT_SKIP_KEYWORDS.some(
      (keyword) => contextWindow.includes(keyword),
    );
    if (isContentContext) {
      continue;
    }

    // Skip if the string is a JSON value for a safe key like "content", "text", etc.
    const jsonKeyWindow = content.slice(
      Math.max(0, matchStart - 60),
      matchStart,
    );
    if (JSON_SAFE_KEY_PATTERN.test(jsonKeyWindow)) {
      continue;
    }

    // Also skip if any existing finding overlaps this range
    const overlaps = findings.some((f) => {
      const fStart = content.indexOf(f.match.replace(/\*+/g, ""));
      // Use line-based overlap as a rough heuristic
      const pos = getPosition(content, matchStart);
      return f.line === pos.line && f.filePath === filePath;
    });

    if (overlaps) {
      continue;
    }

    // Enforce per-file cap on entropy findings
    entropyFindingCount++;
    if (entropyFindingCount > ENTROPY_MAX_PER_FILE) {
      break;
    }

    seenOffsets.add(offsetKey);
    const pos = getPosition(content, matchStart);

    findings.push({
      id: randomUUID(),
      secretType: `High-Entropy String (entropy: ${entropy.toFixed(2)})`,
      severity: "low",
      match: redact(candidate),
      filePath,
      line: pos.line,
      column: pos.column,
      platform,
      context: extractContext(content, matchStart, matchEnd),
    });
  }

  return findings;
}
