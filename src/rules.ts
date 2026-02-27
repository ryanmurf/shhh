import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Severity } from "./types.js";

/**
 * A custom rule definition as read from JSON configuration.
 */
export interface CustomRuleDefinition {
  name: string;
  pattern: string;
  severity: string;
}

/**
 * A compiled custom rule ready to be used by the detector.
 * Compatible with the SecretPattern interface in detector.ts.
 */
export interface CustomRule {
  name: string;
  severity: Severity;
  pattern: RegExp;
}

/**
 * Valid severity levels for custom rules.
 */
const VALID_SEVERITIES: readonly string[] = ["critical", "high", "medium", "low"];

/**
 * Default path for the custom rules configuration file.
 */
function defaultConfigPath(): string {
  return join(homedir(), ".config", "shhh", "rules.json");
}

/**
 * Validate that a rule definition has the required shape and valid values.
 * Returns an error message string if invalid, or null if valid.
 */
function validateRuleDefinition(rule: unknown, index: number): string | null {
  if (typeof rule !== "object" || rule === null || Array.isArray(rule)) {
    return `Rule at index ${index}: must be an object`;
  }

  const obj = rule as Record<string, unknown>;

  if (typeof obj.name !== "string" || obj.name.trim() === "") {
    return `Rule at index ${index}: "name" must be a non-empty string`;
  }

  if (typeof obj.pattern !== "string" || obj.pattern.trim() === "") {
    return `Rule at index ${index} ("${obj.name}"): "pattern" must be a non-empty string`;
  }

  if (typeof obj.severity !== "string") {
    return `Rule at index ${index} ("${obj.name}"): "severity" must be a string`;
  }

  if (!VALID_SEVERITIES.includes(obj.severity)) {
    return `Rule at index ${index} ("${obj.name}"): invalid severity "${obj.severity}". Must be one of: ${VALID_SEVERITIES.join(", ")}`;
  }

  return null;
}

/**
 * Load custom rules from a JSON configuration file.
 *
 * By default, reads from `~/.config/shhh/rules.json`. The file should contain
 * a JSON array of rule objects, each with:
 *   - name: string - descriptive name for the rule
 *   - pattern: string - regex pattern to match against content
 *   - severity: "critical" | "high" | "medium" | "low"
 *
 * Invalid rules (bad regex, missing fields, etc.) are skipped with a warning
 * to stderr. If the file does not exist, an empty array is returned.
 *
 * @param configPath - Optional path to the rules JSON file
 * @returns Array of compiled CustomRule objects ready for the detector
 */
export function loadCustomRules(configPath?: string): CustomRule[] {
  const filePath = configPath ?? defaultConfigPath();

  let raw: string;
  try {
    raw = readFileSync(filePath, "utf-8");
  } catch {
    // File does not exist or is not readable — this is not an error
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`shhh: Failed to parse rules file ${filePath}: ${message}\n`);
    return [];
  }

  if (!Array.isArray(parsed)) {
    process.stderr.write(`shhh: Rules file ${filePath} must contain a JSON array\n`);
    return [];
  }

  const rules: CustomRule[] = [];

  for (let i = 0; i < parsed.length; i++) {
    const item = parsed[i];

    // Validate rule shape and field values
    const validationError = validateRuleDefinition(item, i);
    if (validationError) {
      process.stderr.write(`shhh: ${validationError} — skipping\n`);
      continue;
    }

    const def = item as CustomRuleDefinition;

    // Try to compile the regex pattern
    let compiled: RegExp;
    try {
      compiled = new RegExp(def.pattern, "g");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(
        `shhh: Rule "${def.name}" has invalid regex "${def.pattern}": ${message} — skipping\n`,
      );
      continue;
    }

    rules.push({
      name: def.name,
      severity: def.severity as Severity,
      pattern: compiled,
    });
  }

  return rules;
}
