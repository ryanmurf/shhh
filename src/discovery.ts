import { readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import type { Platform, SessionFile } from "./types.js";

/**
 * Platform configuration: where to look and which file extensions to match.
 */
interface PlatformConfig {
  platform: Platform;
  baseDir: string;
  extensions: string[];
}

/**
 * Options for discoverSessionFiles.
 */
interface DiscoverOptions {
  platform?: Platform;
}

/**
 * Patterns to match variant directories in the home folder.
 * Each entry defines a prefix to match against dotfiles/dotdirs in $HOME,
 * so that non-standard folders like ~/.claude-hd, ~/.claude-max, ~/.codex-beta
 * are automatically discovered alongside the standard ones.
 */
interface PlatformPattern {
  platform: Platform;
  /** Prefix to match (e.g., ".claude" matches ".claude", ".claude-hd", ".claude-max") */
  prefix: string;
  extensions: string[];
  /** Fixed paths that don't follow the prefix pattern (e.g., ~/.config/github-copilot) */
  fixedPaths?: string[];
}

const PLATFORM_PATTERNS: PlatformPattern[] = [
  {
    platform: "claude",
    prefix: ".claude",
    extensions: [".jsonl", ".json"],
  },
  {
    platform: "codex",
    prefix: ".codex",
    extensions: [".jsonl"],
  },
  {
    platform: "copilot",
    prefix: ".copilot",
    extensions: [".json", ".log"],
    fixedPaths: [".config/github-copilot"],
  },
];

/**
 * Build platform configurations by scanning the home directory for
 * both standard and variant directories (e.g., .claude-hd, .claude-max).
 */
function getPlatformConfigs(): PlatformConfig[] {
  const home = homedir();
  const configs: PlatformConfig[] = [];

  // Scan home directory for variant folders
  let homeEntries: string[] = [];
  try {
    homeEntries = readdirSync(home);
  } catch {
    // If we can't read home, fall back to just the fixed paths
  }

  for (const pattern of PLATFORM_PATTERNS) {
    // Match variant directories: .claude, .claude-hd, .claude-max, etc.
    // Must start with the prefix, then either end or have a non-alphanumeric separator
    for (const entry of homeEntries) {
      if (
        entry === pattern.prefix ||
        (entry.startsWith(pattern.prefix) &&
          (entry[pattern.prefix.length] === "-" ||
            entry[pattern.prefix.length] === "." ||
            entry[pattern.prefix.length] === "_"))
      ) {
        const fullPath = join(home, entry);
        try {
          if (statSync(fullPath).isDirectory()) {
            configs.push({
              platform: pattern.platform,
              baseDir: fullPath,
              extensions: pattern.extensions,
            });
          }
        } catch {
          // Not a directory or not readable, skip
        }
      }
    }

    // Also add any fixed paths (like ~/.config/github-copilot)
    if (pattern.fixedPaths) {
      for (const fixedPath of pattern.fixedPaths) {
        const fullPath = join(home, fixedPath);
        // Avoid duplicates if it was already matched
        if (!configs.some((c) => c.baseDir === fullPath)) {
          configs.push({
            platform: pattern.platform,
            baseDir: fullPath,
            extensions: pattern.extensions,
          });
        }
      }
    }
  }

  return configs;
}

/**
 * Recursively walk a directory and collect files matching the given extensions.
 */
function walkDirectory(
  dir: string,
  extensions: string[],
): string[] {
  const results: string[] = [];

  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    // Directory doesn't exist or is not readable
    return results;
  }

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      // Skip node_modules and hidden dirs other than the base
      if (entry.name === "node_modules") {
        continue;
      }
      const nested = walkDirectory(fullPath, extensions);
      results.push(...nested);
    } else if (entry.isFile()) {
      const matchesExtension = extensions.some((ext) =>
        entry.name.endsWith(ext),
      );
      if (matchesExtension) {
        results.push(fullPath);
      }
    }
  }

  return results;
}

/**
 * Discover session files for the specified platform(s).
 *
 * If a platform is specified, only files for that platform are discovered.
 * If no platform is given, all supported platforms are scanned.
 *
 * Accepts either a Platform string or an options object { platform?: Platform }.
 *
 * @param options - Optional platform filter (string or { platform?: Platform })
 * @returns Array of SessionFile objects with platform and absolute file path
 */
export function discoverSessionFiles(
  options?: Platform | DiscoverOptions,
): SessionFile[] {
  const configs = getPlatformConfigs();

  // Normalize: accept both a plain Platform string and an options object
  let platform: Platform | undefined;
  if (typeof options === "string") {
    platform = options;
  } else if (options && typeof options === "object" && "platform" in options) {
    platform = options.platform;
  }

  const targetConfigs = platform
    ? configs.filter((c) => c.platform === platform)
    : configs;

  const sessionFiles: SessionFile[] = [];

  for (const config of targetConfigs) {
    // Verify the base directory exists
    try {
      const dirStat = statSync(config.baseDir);
      if (!dirStat.isDirectory()) {
        continue;
      }
    } catch {
      // Base directory doesn't exist, skip
      continue;
    }

    const files = walkDirectory(config.baseDir, config.extensions);

    for (const filePath of files) {
      sessionFiles.push({
        platform: config.platform,
        filePath: resolve(filePath),
      });
    }
  }

  return sessionFiles;
}
