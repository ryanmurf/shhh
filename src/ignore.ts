import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { minimatch } from "minimatch";
import type { Finding, Platform } from "./types.js";

/**
 * Parsed ignore rules from .shhhignore files.
 */
export interface IgnoreRules {
  /** Literal strings — if found in a finding's match (un-redacted) or context, skip it */
  literals: string[];
  /** Secret type prefixes — skip all findings whose secretType starts with the value */
  types: string[];
  /** File path globs — skip files matching these patterns */
  fileGlobs: string[];
  /** Platform names — skip entire platforms */
  platforms: string[];
}

/**
 * Parse the contents of a single .shhhignore file into rule arrays.
 */
function parseIgnoreContent(content: string): IgnoreRules {
  const rules: IgnoreRules = {
    literals: [],
    types: [],
    fileGlobs: [],
    platforms: [],
  };

  const lines = content.split("\n");

  for (const rawLine of lines) {
    const line = rawLine.trim();

    // Skip blank lines and comments
    if (line === "" || line.startsWith("#")) {
      continue;
    }

    if (line.startsWith("type:")) {
      const value = line.slice("type:".length).trim();
      if (value) {
        rules.types.push(value);
      }
    } else if (line.startsWith("file:")) {
      const value = line.slice("file:".length).trim();
      if (value) {
        rules.fileGlobs.push(value);
      }
    } else if (line.startsWith("platform:")) {
      const value = line.slice("platform:".length).trim();
      if (value) {
        rules.platforms.push(value);
      }
    } else {
      // Literal string to ignore
      rules.literals.push(line);
    }
  }

  return rules;
}

/**
 * Merge two IgnoreRules objects into one, concatenating all arrays.
 */
function mergeRules(a: IgnoreRules, b: IgnoreRules): IgnoreRules {
  return {
    literals: [...a.literals, ...b.literals],
    types: [...a.types, ...b.types],
    fileGlobs: [...a.fileGlobs, ...b.fileGlobs],
    platforms: [...a.platforms, ...b.platforms],
  };
}

/**
 * Try to read a file and return its contents, or null if it doesn't exist.
 */
function tryReadFile(filePath: string): string | null {
  try {
    return readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}

/**
 * Load ignore rules from .shhhignore files.
 *
 * Searches for .shhhignore in:
 *   1. The given directory (defaults to process.cwd())
 *   2. ~/.config/shhh/.shhhignore (global config)
 *
 * Rules from both files are merged, with all rules combined additively.
 *
 * @param dir - The directory to look for a local .shhhignore file (defaults to cwd)
 * @returns Parsed and merged IgnoreRules
 */
export function loadIgnoreRules(dir?: string): IgnoreRules {
  const baseDir = dir ?? process.cwd();

  const emptyRules: IgnoreRules = {
    literals: [],
    types: [],
    fileGlobs: [],
    platforms: [],
  };

  let merged = emptyRules;

  // 1. Local .shhhignore
  const localPath = join(resolve(baseDir), ".shhhignore");
  const localContent = tryReadFile(localPath);
  if (localContent !== null) {
    merged = mergeRules(merged, parseIgnoreContent(localContent));
  }

  // 2. Global ~/.config/shhh/.shhhignore
  const globalPath = join(homedir(), ".config", "shhh", ".shhhignore");
  const globalContent = tryReadFile(globalPath);
  if (globalContent !== null) {
    merged = mergeRules(merged, parseIgnoreContent(globalContent));
  }

  return merged;
}

/**
 * Check whether a file path should be ignored based on file glob rules.
 *
 * @param filePath - The absolute file path to check
 * @param rules - The loaded ignore rules
 * @returns true if the file should be skipped
 */
export function shouldIgnoreFile(filePath: string, rules: IgnoreRules): boolean {
  for (const glob of rules.fileGlobs) {
    if (minimatch(filePath, glob, { dot: true })) {
      return true;
    }
  }
  return false;
}

/**
 * Check whether a finding should be ignored based on ignore rules.
 *
 * A finding is ignored if any of the following match:
 *   - Its platform matches a `platform:` rule (case-insensitive)
 *   - Its secretType starts with a `type:` rule value (case-insensitive)
 *   - Its match or context contains a literal ignore string
 *   - Its filePath matches a `file:` glob
 *
 * @param finding - The finding to check
 * @param rules - The loaded ignore rules
 * @returns true if the finding should be excluded from results
 */
export function shouldIgnore(finding: Finding, rules: IgnoreRules): boolean {
  // Check platform rules
  for (const platform of rules.platforms) {
    if (finding.platform.toLowerCase() === platform.toLowerCase()) {
      return true;
    }
  }

  // Check type rules — match if the finding's secretType starts with the rule value
  for (const typePrefix of rules.types) {
    if (
      finding.secretType.toLowerCase().startsWith(typePrefix.toLowerCase())
    ) {
      return true;
    }
  }

  // Check literal rules — match against context (which contains a redacted
  // version of the match) and the match field itself
  for (const literal of rules.literals) {
    if (finding.match.includes(literal) || finding.context.includes(literal)) {
      return true;
    }
  }

  // Check file glob rules
  for (const glob of rules.fileGlobs) {
    if (minimatch(finding.filePath, glob, { dot: true })) {
      return true;
    }
  }

  return false;
}
