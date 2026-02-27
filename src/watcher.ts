import { watch, statSync, readSync, openSync, closeSync, type FSWatcher } from "node:fs";
import { readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { discoverSessionFiles } from "./discovery.js";
import { detectSecrets, type SecretPattern } from "./detector.js";
import { formatText } from "./reporter.js";
import { loadCustomRules } from "./rules.js";
import type { Platform, Finding, ScanResult } from "./types.js";

/**
 * Options for the watchSessions function.
 */
export interface WatchOptions {
  /** Filter to watch only a specific platform */
  platform?: Platform;
  /** Optional custom rules to run alongside built-in patterns */
  customRules?: SecretPattern[];
}

/**
 * Track the last known size of each file so we only read new content.
 */
const fileSizes = new Map<string, number>();

/**
 * Active file system watchers, so we can clean them up on SIGINT.
 */
const activeWatchers: FSWatcher[] = [];

/**
 * Read only the new content appended to a file since the last known position.
 *
 * @param filePath - Absolute path to the file
 * @returns The new content, or null if no new content or the file shrank
 */
function readNewContent(filePath: string): string | null {
  let stat;
  try {
    stat = statSync(filePath);
  } catch {
    return null;
  }

  const lastSize = fileSizes.get(filePath) ?? 0;
  const currentSize = stat.size;

  if (currentSize <= lastSize) {
    // File has not grown (or was truncated); update tracked size and skip
    fileSizes.set(filePath, currentSize);
    return null;
  }

  const bytesToRead = currentSize - lastSize;
  const buffer = Buffer.alloc(bytesToRead);

  let fd: number;
  try {
    fd = openSync(filePath, "r");
  } catch {
    return null;
  }

  try {
    const bytesRead = readSync(fd, buffer, 0, bytesToRead, lastSize);
    fileSizes.set(filePath, currentSize);
    return buffer.toString("utf-8", 0, bytesRead);
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

/**
 * Process a file change event: read new content, run detection, and print findings.
 */
function handleFileChange(filePath: string, platform: Platform, customRules?: SecretPattern[]): void {
  const newContent = readNewContent(filePath);
  if (!newContent) {
    return;
  }

  const findings: Finding[] = detectSecrets(newContent, filePath, platform, customRules);

  if (findings.length > 0) {
    const result: ScanResult = {
      findings,
      filesScanned: 1,
      platformsScanned: [platform],
      scanDurationMs: 0,
    };

    const output = formatText(result);
    process.stdout.write(output);
  }
}

/**
 * Initialize the file size tracker for a file so we only detect new content going forward.
 */
function initializeFileSize(filePath: string): void {
  try {
    const stat = statSync(filePath);
    fileSizes.set(filePath, stat.size);
  } catch {
    fileSizes.set(filePath, 0);
  }
}

/**
 * Collect unique directories from a list of session files.
 */
function getUniqueDirectories(files: Array<{ filePath: string }>): Set<string> {
  const dirs = new Set<string>();
  for (const { filePath } of files) {
    dirs.add(dirname(filePath));
  }
  return dirs;
}

/**
 * Clean up all active watchers.
 */
function cleanupWatchers(): void {
  for (const watcher of activeWatchers) {
    try {
      watcher.close();
    } catch {
      // Ignore errors during cleanup
    }
  }
  activeWatchers.length = 0;
  fileSizes.clear();
}

/**
 * Watch AI assistant session directories for real-time secret detection.
 *
 * Monitors session file directories using `fs.watch` and runs the secret
 * detector on any new content appended to session files. Findings are
 * immediately printed to stdout using the text reporter.
 *
 * Runs until terminated with SIGINT (Ctrl+C).
 *
 * @param options - Optional platform filter and custom rules
 */
export function watchSessions(options?: WatchOptions): void {
  const platform = options?.platform;
  const customRules = options?.customRules ?? loadCustomRules();

  // Discover existing session files to determine which directories to watch
  const sessionFiles = platform
    ? discoverSessionFiles(platform)
    : discoverSessionFiles();

  if (sessionFiles.length === 0) {
    process.stderr.write("No session directories found to watch.\n");
    return;
  }

  // Build a lookup of which platform each directory belongs to
  const dirPlatformMap = new Map<string, Platform>();
  for (const { filePath, platform: p } of sessionFiles) {
    const dir = dirname(filePath);
    dirPlatformMap.set(dir, p);
  }

  // Initialize tracked file sizes for all existing files
  for (const { filePath } of sessionFiles) {
    initializeFileSize(filePath);
  }

  const directories = getUniqueDirectories(sessionFiles);

  // Determine which file extensions to watch per platform
  const platformExtensions: Record<Platform, string[]> = {
    claude: [".jsonl", ".json"],
    codex: [".jsonl"],
    copilot: [".json", ".log"],
  };

  // Set up watchers on each directory
  for (const dir of directories) {
    const dirPlatform = dirPlatformMap.get(dir);
    if (!dirPlatform) continue;

    const extensions = platformExtensions[dirPlatform];

    try {
      const watcher = watch(dir, { persistent: true }, (eventType, filename) => {
        if (!filename) return;

        // Only process files matching the platform's expected extensions
        const matchesExtension = extensions.some((ext) => filename.endsWith(ext));
        if (!matchesExtension) return;

        const fullPath = join(dir, filename);

        // For newly created files, initialize their size to 0 so we read all content
        if (!fileSizes.has(fullPath)) {
          fileSizes.set(fullPath, 0);
        }

        handleFileChange(fullPath, dirPlatform, customRules.length > 0 ? customRules : undefined);
      });

      activeWatchers.push(watcher);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`Warning: Could not watch ${dir}: ${message}\n`);
    }
  }

  process.stderr.write(`Watching ${directories.size} directories for changes...\n`);

  // Clean up on SIGINT
  const sigintHandler = (): void => {
    process.stderr.write("\nStopping watcher...\n");
    cleanupWatchers();
    process.exit(0);
  };

  process.on("SIGINT", sigintHandler);
}
