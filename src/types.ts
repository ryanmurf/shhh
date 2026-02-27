export type Severity = "critical" | "high" | "medium" | "low";

export type Platform = "claude" | "codex" | "copilot";

export interface Finding {
  /** Unique identifier for this finding */
  id: string;
  /** The type of secret detected (e.g. "AWS Access Key", "GitHub Token") */
  secretType: string;
  /** Severity level of the finding */
  severity: Severity;
  /** The matched string, redacted to avoid further exposure */
  match: string;
  /** Absolute path to the file containing the secret */
  filePath: string;
  /** Line number where the secret was found (1-based) */
  line: number;
  /** Column number where the secret starts (1-based) */
  column: number;
  /** Which AI assistant platform the file belongs to */
  platform: Platform;
  /** Surrounding text context, also redacted */
  context: string;
}

export interface SessionFile {
  platform: Platform;
  filePath: string;
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  platformsScanned: Platform[];
  scanDurationMs: number;
}
