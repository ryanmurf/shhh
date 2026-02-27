import { readFileSync, writeFileSync, mkdirSync, unlinkSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Per-file incremental scan state.
 */
export interface FileState {
  /** Byte offset up to which this file has been scanned */
  lastScannedByte: number;
  /** ISO 8601 timestamp of the file's last modification time when it was scanned */
  lastModified: string;
  /** Number of findings detected in this file */
  findingsCount: number;
  /** Number of lines scanned so far (used for correct line numbering in incremental scans) */
  linesScanned?: number;
}

/**
 * Top-level scan state persisted to disk.
 */
export interface ScanState {
  /** ISO 8601 timestamp of the last completed scan */
  lastScan: string;
  /** Map of absolute file paths to their individual scan state */
  files: Record<string, FileState>;
}

/**
 * Compute the state directory path lazily so that changes to $HOME
 * (e.g. in tests) are respected.
 */
function stateDir(): string {
  return join(homedir(), ".config", "shhh");
}

/**
 * Compute the state file path lazily.
 */
function stateFile(): string {
  return join(stateDir(), "scan-state.json");
}

/**
 * Get the path to the scan state file. Exported for testing and for the
 * `clean` command.
 */
export function getStateFilePath(): string {
  return stateFile();
}

/**
 * Load the scan state from disk. Returns a fresh empty state if the file
 * does not exist or cannot be parsed.
 */
export function loadScanState(): ScanState {
  try {
    const raw = readFileSync(stateFile(), "utf-8");
    const parsed = JSON.parse(raw) as ScanState;

    // Basic shape validation — also reject arrays masquerading as objects
    if (
      typeof parsed.lastScan !== "string" ||
      typeof parsed.files !== "object" ||
      parsed.files === null ||
      Array.isArray(parsed.files)
    ) {
      return emptyState();
    }

    return parsed;
  } catch {
    return emptyState();
  }
}

/**
 * Persist the scan state to disk. Creates the config directory if needed.
 */
export function saveScanState(state: ScanState): void {
  const dir = stateDir();
  mkdirSync(dir, { recursive: true });
  writeFileSync(stateFile(), JSON.stringify(state, null, 2), "utf-8");
}

/**
 * Retrieve the incremental state for a specific file, or null if no
 * previous state exists.
 */
export function getFileState(state: ScanState, filePath: string): FileState | null {
  return state.files[filePath] ?? null;
}

/**
 * Update (or create) the incremental state entry for a file after scanning.
 *
 * @param mtime - The file's last-modification time (from stat). When
 *   provided the state records the file's real mtime so that the next
 *   incremental scan can detect whether the file changed.  Falls back to
 *   the current wall-clock time when omitted (legacy behaviour).
 * @param linesScanned - Total number of lines processed so far, used to
 *   provide correct absolute line numbers when resuming incremental scans.
 */
export function updateFileState(
  state: ScanState,
  filePath: string,
  scannedBytes: number,
  findingsCount: number,
  mtime?: Date,
  linesScanned?: number,
): void {
  state.files[filePath] = {
    lastScannedByte: scannedBytes,
    lastModified: mtime ? mtime.toISOString() : new Date().toISOString(),
    findingsCount,
    linesScanned: linesScanned ?? 0,
  };
}

/**
 * Delete the state file from disk, effectively resetting incremental state.
 * Returns true if the file was deleted, false if it did not exist.
 */
export function deleteScanState(): boolean {
  try {
    const file = stateFile();
    if (existsSync(file)) {
      unlinkSync(file);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Helper to create a fresh empty state.
 */
function emptyState(): ScanState {
  return {
    lastScan: new Date().toISOString(),
    files: {},
  };
}
