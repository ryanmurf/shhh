import { readFileSync, statSync } from "node:fs";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import { discoverSessionFiles } from "./discovery.js";
import { detectSecrets } from "./detector.js";
import {
  loadIgnoreRules,
  shouldIgnore,
  shouldIgnoreFile,
  type IgnoreRules,
} from "./ignore.js";
import type { Finding, Platform, ScanResult } from "./types.js";
import type { ScanState } from "./state.js";
import { getFileState, updateFileState } from "./state.js";

/**
 * Maximum file size to scan (50 MB). Files larger than this are skipped.
 */
const MAX_FILE_SIZE = 50 * 1024 * 1024;

/**
 * Maximum number of files to process concurrently.
 */
const CONCURRENCY_LIMIT = 8;

/**
 * Process an array of tasks with a concurrency limit.
 * Runs up to `limit` tasks in parallel, starting the next one as each completes.
 */
async function parallelMap<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;

  async function worker(): Promise<void> {
    while (nextIndex < items.length) {
      const index = nextIndex++;
      results[index] = await fn(items[index]);
    }
  }

  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(limit, items.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  return results;
}

/**
 * Check whether a file path looks like a JSONL/log file (line-delimited format
 * that supports incremental offset-based scanning).
 */
function isJsonlFile(filePath: string): boolean {
  return filePath.endsWith(".jsonl") || filePath.endsWith(".log");
}

/**
 * Scan a single file for secrets, processing line-by-line for performance.
 *
 * For JSONL/log files (which are line-delimited), this avoids loading
 * the entire file into memory and running regex over a massive string.
 *
 * When an incremental ScanState is provided, files that have not been
 * modified since the last scan are skipped entirely.  For JSONL files
 * that have grown, scanning resumes from the previous byte offset.
 */
async function scanFile(
  filePath: string,
  platform: Platform,
  scanState?: ScanState,
): Promise<Finding[]> {
  try {
    const stat = statSync(filePath);
    if (stat.size > MAX_FILE_SIZE) {
      process.stderr.write(
        `  Skipping ${filePath} (${(stat.size / 1024 / 1024).toFixed(0)}MB > ${MAX_FILE_SIZE / 1024 / 1024}MB limit)\n`,
      );
      return [];
    }

    // --- Incremental skip / offset logic ---
    let startByte = 0;
    let lineOffset = 0;
    if (scanState) {
      const fileState = getFileState(scanState, filePath);
      if (fileState) {
        const currentMtime = stat.mtime.toISOString();
        // File has not been modified since last scan — skip entirely
        if (currentMtime === fileState.lastModified) {
          return [];
        }
        // For JSONL/log files that grew, resume from the last scanned offset
        if (isJsonlFile(filePath) && stat.size > fileState.lastScannedByte) {
          startByte = fileState.lastScannedByte;
          lineOffset = fileState.linesScanned ?? 0;
        }
      }
    }

    // For small files (< 1MB) with no byte offset, read all at once — faster than streaming
    if (stat.size < 1 * 1024 * 1024 && startByte === 0) {
      const content = readFileSync(filePath, "utf-8");
      const findings = detectSecrets(content, filePath, platform);

      // Count lines for incremental state tracking
      const totalLines = content.split("\n").length;

      if (scanState) {
        updateFileState(scanState, filePath, stat.size, findings.length, stat.mtime, totalLines);
      }

      return findings;
    }

    // For larger files (or incremental offset scans), process line-by-line
    const findings: Finding[] = [];
    let lineNumber = lineOffset;
    let bytesConsumed = 0;

    const rl = createInterface({
      input: createReadStream(filePath, { encoding: "utf-8", start: startByte }),
      crlfDelay: Infinity,
    });

    for await (const line of rl) {
      lineNumber++;
      // Track bytes consumed (line bytes + newline character)
      bytesConsumed += Buffer.byteLength(line, "utf-8") + 1;

      // Skip empty lines
      if (line.length === 0) continue;

      const lineFindings = detectSecrets(line, filePath, platform);

      // Adjust line numbers — detectSecrets reports line 1 for each chunk,
      // but we know the real absolute line number
      for (const finding of lineFindings) {
        finding.line = lineNumber;
        findings.push(finding);
      }
    }

    if (scanState) {
      updateFileState(scanState, filePath, startByte + bytesConsumed, findings.length, stat.mtime, lineNumber);
    }

    return findings;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`  Warning: Could not read ${filePath}: ${message}\n`);
    return [];
  }
}

/**
 * Options for scan functions.
 */
export interface ScanOptions {
  /** If true, ignore rules from .shhhignore files are not applied. */
  noIgnore?: boolean;
  /** When provided, enables incremental scanning using this state. */
  scanState?: ScanState;
}

/**
 * Scan all supported platforms for leaked secrets.
 */
export async function scanAll(options?: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();

  const ignoreRules = options?.noIgnore ? null : loadIgnoreRules();
  const scanState = options?.scanState;

  let sessionFiles = discoverSessionFiles();

  // Filter out files matching file: ignore globs before scanning
  if (ignoreRules) {
    sessionFiles = sessionFiles.filter(
      ({ filePath }) => !shouldIgnoreFile(filePath, ignoreRules),
    );
  }

  const allFindings: Finding[] = [];
  const platformsSeen = new Set<Platform>();

  process.stderr.write(`Scanning ${sessionFiles.length} session files...\n`);

  for (const { platform } of sessionFiles) {
    platformsSeen.add(platform);
  }

  const isTTY = process.stderr.isTTY;
  let scanned = 0;
  const results = await parallelMap(
    sessionFiles,
    CONCURRENCY_LIMIT,
    async ({ platform, filePath }) => {
      const findings = await scanFile(filePath, platform, scanState);
      scanned++;
      if (isTTY) {
        process.stderr.write(
          `\r  [${scanned}/${sessionFiles.length}] ${platform}: ${filePath.replace(/^.*\//, "").padEnd(60)}`,
        );
      }
      return findings;
    },
  );

  for (const findings of results) {
    allFindings.push(...findings);
  }

  if (isTTY) {
    process.stderr.write("\n");
  }

  // Filter out findings matching ignore rules after detection
  const filteredFindings = ignoreRules
    ? allFindings.filter((f) => !shouldIgnore(f, ignoreRules))
    : allFindings;

  return {
    findings: filteredFindings,
    filesScanned: sessionFiles.length,
    platformsScanned: Array.from(platformsSeen),
    scanDurationMs: Date.now() - startTime,
  };
}

/**
 * Scan a specific platform for leaked secrets.
 */
export async function scanPlatform(
  platform: Platform,
  options?: ScanOptions,
): Promise<ScanResult> {
  const startTime = Date.now();

  const ignoreRules = options?.noIgnore ? null : loadIgnoreRules();
  const scanState = options?.scanState;

  let sessionFiles = discoverSessionFiles(platform);

  // Filter out files matching file: ignore globs before scanning
  if (ignoreRules) {
    sessionFiles = sessionFiles.filter(
      ({ filePath }) => !shouldIgnoreFile(filePath, ignoreRules),
    );
  }

  const allFindings: Finding[] = [];

  process.stderr.write(
    `Scanning ${sessionFiles.length} ${platform} session files...\n`,
  );

  const isTTY = process.stderr.isTTY;
  let scanned = 0;
  const results = await parallelMap(
    sessionFiles,
    CONCURRENCY_LIMIT,
    async ({ filePath }) => {
      const findings = await scanFile(filePath, platform, scanState);
      scanned++;
      if (isTTY) {
        process.stderr.write(
          `\r  [${scanned}/${sessionFiles.length}] ${filePath.replace(/^.*\//, "").padEnd(60)}`,
        );
      }
      return findings;
    },
  );

  for (const findings of results) {
    allFindings.push(...findings);
  }

  if (isTTY) {
    process.stderr.write("\n");
  }

  // Filter out findings matching ignore rules after detection
  const filteredFindings = ignoreRules
    ? allFindings.filter((f) => !shouldIgnore(f, ignoreRules))
    : allFindings;

  return {
    findings: filteredFindings,
    filesScanned: sessionFiles.length,
    platformsScanned: sessionFiles.length > 0 ? [platform] : [],
    scanDurationMs: Date.now() - startTime,
  };
}
