import { readFileSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import type { Finding } from "./types.js";

/**
 * Options for the redaction process.
 */
export interface RedactOptions {
  /** If true, show what would be redacted without modifying files */
  dryRun?: boolean;
  /** If true, create .bak files before modifying (default true) */
  backup?: boolean;
  /** If provided, called for each finding — return true to redact, false to skip */
  filterFn?: (finding: Finding) => boolean;
}

/**
 * Result of a redaction operation.
 */
export interface RedactResult {
  filesModified: number;
  secretsRedacted: number;
  errors: string[];
}

/**
 * Build the redaction placeholder for a finding.
 *
 * Format: [REDACTED:secret_type:first4chars]
 *
 * The secret_type is derived from the finding's secretType, with spaces
 * replaced by underscores.  The first4chars come from the finding's
 * `match` field (which is already partially redacted by the detector).
 * We extract the leading characters before any asterisks as the prefix.
 */
export function buildPlaceholder(finding: Finding): string {
  const typeTag = finding.secretType.replace(/\s+/g, "_");
  // The match field is redacted like "ghp_****ghij".  Extract the
  // characters before the first '*' sequence as the prefix hint.
  const starIdx = finding.match.indexOf("*");
  const prefix = starIdx >= 0 ? finding.match.slice(0, starIdx) : finding.match.slice(0, 4);
  return `[REDACTED:${typeTag}:${prefix}]`;
}

/**
 * Given the original secret text on a line and the column (1-based),
 * locate the secret value in the line and replace it with the placeholder.
 *
 * The detector stores `match` as a redacted form (e.g. "ghp_****ghij"),
 * so we cannot use it directly for replacement.  Instead, we look at the
 * column offset on the line and use the match field to figure out the
 * approximate length of the secret, then replace that span.
 *
 * Strategy: Starting at column-1 in the line, read forward to find a
 * contiguous token (non-whitespace, non-quote boundary) and replace it.
 * We use a heuristic: from the column position, grab everything that
 * looks like a token character (not whitespace, not common JSON
 * delimiters).
 */
function findSecretSpan(
  line: string,
  column: number,
): { start: number; end: number } | null {
  const startIdx = column - 1; // column is 1-based
  if (startIdx < 0 || startIdx >= line.length) {
    return null;
  }

  // Walk forward from startIdx to find the end of the token.
  // A secret token typically consists of alphanumeric, +, /, =, _, -, .
  // and certain prefix characters like : for private keys.
  // We also handle private key headers which include spaces and dashes.
  const ch = line[startIdx];

  // Special case: private key headers like "-----BEGIN RSA PRIVATE KEY-----"
  if (ch === "-" && line.slice(startIdx).startsWith("-----BEGIN")) {
    const endMarker = "-----";
    // Find the closing -----
    const afterBegin = line.indexOf(endMarker, startIdx + 10);
    if (afterBegin >= 0) {
      return { start: startIdx, end: afterBegin + endMarker.length };
    }
  }

  // Special case: connection strings (postgres://, mysql://, mongodb://)
  if (line.slice(startIdx).match(/^(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\//)) {
    let end = startIdx;
    while (end < line.length && !/[\s"'`<>{}|\\^,;\])]+/.test(line[end])) {
      end++;
    }
    return { start: startIdx, end };
  }

  // General case: walk forward through token characters
  let end = startIdx;
  // Token characters for secrets: alphanumeric plus common secret chars
  const tokenRe = /[A-Za-z0-9+/=_\-.:~]/;
  while (end < line.length && tokenRe.test(line[end])) {
    end++;
  }

  if (end === startIdx) {
    return null;
  }

  return { start: startIdx, end };
}

/**
 * Group findings by their file path so we can process each file once.
 */
function groupByFile(findings: Finding[]): Map<string, Finding[]> {
  const grouped = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = grouped.get(finding.filePath);
    if (existing) {
      existing.push(finding);
    } else {
      grouped.set(finding.filePath, [finding]);
    }
  }
  return grouped;
}

/**
 * Redact found secrets in their source files.
 *
 * For each finding, reads the source file, locates the secret at the
 * reported line/column, and replaces it with a redacted placeholder.
 *
 * Findings are grouped by file to minimize file reads/writes.
 * Within each file, findings are processed from last to first (by line
 * and column, descending) so that earlier replacements do not shift the
 * positions of later ones.
 *
 * @param findings - Array of findings from a scan
 * @param options - Redaction options (dryRun, backup, filterFn)
 * @returns A RedactResult with counts and any errors
 */
export function redactFindings(
  findings: Finding[],
  options?: RedactOptions,
): RedactResult {
  const dryRun = options?.dryRun ?? false;
  const backup = options?.backup ?? true;
  const filterFn = options?.filterFn;

  const result: RedactResult = {
    filesModified: 0,
    secretsRedacted: 0,
    errors: [],
  };

  if (findings.length === 0) {
    return result;
  }

  // Apply interactive filter if provided
  const filteredFindings = filterFn
    ? findings.filter(filterFn)
    : findings;

  if (filteredFindings.length === 0) {
    return result;
  }

  const grouped = groupByFile(filteredFindings);

  for (const [filePath, fileFindings] of grouped) {
    // Check file exists
    if (!existsSync(filePath)) {
      result.errors.push(`File not found: ${filePath}`);
      continue;
    }

    let content: string;
    try {
      content = readFileSync(filePath, "utf-8");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      result.errors.push(`Could not read ${filePath}: ${message}`);
      continue;
    }

    const lines = content.split("\n");

    // Sort findings in reverse order (last line first, then last column first)
    // so replacements don't shift positions of earlier findings.
    const sorted = [...fileFindings].sort((a, b) => {
      if (a.line !== b.line) return b.line - a.line;
      return b.column - a.column;
    });

    let secretsInFile = 0;

    for (const finding of sorted) {
      const lineIdx = finding.line - 1; // line is 1-based
      if (lineIdx < 0 || lineIdx >= lines.length) {
        result.errors.push(
          `Line ${finding.line} out of range in ${filePath} (file has ${lines.length} lines)`,
        );
        continue;
      }

      const line = lines[lineIdx];
      const span = findSecretSpan(line, finding.column);

      if (!span) {
        result.errors.push(
          `Could not locate secret at ${filePath}:${finding.line}:${finding.column}`,
        );
        continue;
      }

      const placeholder = buildPlaceholder(finding);
      const newLine =
        line.slice(0, span.start) + placeholder + line.slice(span.end);

      lines[lineIdx] = newLine;
      secretsInFile++;
    }

    if (secretsInFile === 0) {
      continue;
    }

    if (!dryRun) {
      // Create backup if requested
      if (backup) {
        try {
          copyFileSync(filePath, filePath + ".bak");
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          result.errors.push(`Could not create backup for ${filePath}: ${message}`);
          continue;
        }
      }

      // Write modified content
      try {
        writeFileSync(filePath, lines.join("\n"), "utf-8");
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        result.errors.push(`Could not write ${filePath}: ${message}`);
        continue;
      }
    }

    result.filesModified++;
    result.secretsRedacted += secretsInFile;
  }

  return result;
}
