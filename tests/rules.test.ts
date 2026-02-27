import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { loadCustomRules } from "../src/rules";

/**
 * Create a unique temporary directory for each test.
 */
function makeTempDir(): string {
  const dir = join(tmpdir(), `shhh-rules-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Write a rules JSON file with the given content.
 */
function writeRulesFile(dir: string, content: unknown): string {
  const filePath = join(dir, "rules.json");
  writeFileSync(filePath, JSON.stringify(content), "utf-8");
  return filePath;
}

describe("loadCustomRules", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = makeTempDir();
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  // -------------------------------------------------------------------------
  // 1. Valid rules — basic loading
  // -------------------------------------------------------------------------
  it("should load valid custom rules from a JSON file", () => {
    const rules = [
      { name: "Internal API Key", pattern: "MYCO-[A-Z0-9]{32}", severity: "high" },
      { name: "Internal DB Password", pattern: "dbpass_[a-z0-9]+", severity: "critical" },
    ];
    const filePath = writeRulesFile(tempDir, rules);

    const result = loadCustomRules(filePath);

    expect(result).toHaveLength(2);
    expect(result[0].name).toBe("Internal API Key");
    expect(result[0].severity).toBe("high");
    expect(result[0].pattern).toBeInstanceOf(RegExp);
    expect(result[0].pattern.flags).toContain("g");

    expect(result[1].name).toBe("Internal DB Password");
    expect(result[1].severity).toBe("critical");
  });

  // -------------------------------------------------------------------------
  // 2. Valid rules — all severity levels
  // -------------------------------------------------------------------------
  it("should accept all four valid severity levels", () => {
    const rules = [
      { name: "Critical Rule", pattern: "crit_[0-9]+", severity: "critical" },
      { name: "High Rule", pattern: "high_[0-9]+", severity: "high" },
      { name: "Medium Rule", pattern: "med_[0-9]+", severity: "medium" },
      { name: "Low Rule", pattern: "low_[0-9]+", severity: "low" },
    ];
    const filePath = writeRulesFile(tempDir, rules);

    const result = loadCustomRules(filePath);

    expect(result).toHaveLength(4);
    expect(result[0].severity).toBe("critical");
    expect(result[1].severity).toBe("high");
    expect(result[2].severity).toBe("medium");
    expect(result[3].severity).toBe("low");
  });

  // -------------------------------------------------------------------------
  // 3. Invalid regex — skip with warning
  // -------------------------------------------------------------------------
  it("should skip rules with invalid regex and warn to stderr", () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    const rules = [
      { name: "Bad Regex Rule", pattern: "[invalid(regex", severity: "high" },
      { name: "Good Rule", pattern: "good_[0-9]+", severity: "medium" },
    ];
    const filePath = writeRulesFile(tempDir, rules);

    const result = loadCustomRules(filePath);

    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("Good Rule");

    // Verify warning was written to stderr
    expect(stderrSpy).toHaveBeenCalled();
    const stderrOutput = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
    expect(stderrOutput).toContain("Bad Regex Rule");
    expect(stderrOutput).toContain("invalid regex");

    stderrSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 4. Missing file — return empty array
  // -------------------------------------------------------------------------
  it("should return an empty array when the config file does not exist", () => {
    const nonexistentPath = join(tempDir, "nonexistent", "rules.json");

    const result = loadCustomRules(nonexistentPath);

    expect(result).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // 5. Empty array — return empty
  // -------------------------------------------------------------------------
  it("should return an empty array when the config file contains an empty array", () => {
    const filePath = writeRulesFile(tempDir, []);

    const result = loadCustomRules(filePath);

    expect(result).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // 6. Invalid severity — skip with warning
  // -------------------------------------------------------------------------
  it("should skip rules with invalid severity values", () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    const rules = [
      { name: "Bad Severity Rule", pattern: "test_[0-9]+", severity: "extreme" },
      { name: "Valid Rule", pattern: "valid_[0-9]+", severity: "low" },
    ];
    const filePath = writeRulesFile(tempDir, rules);

    const result = loadCustomRules(filePath);

    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("Valid Rule");

    const stderrOutput = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
    expect(stderrOutput).toContain("invalid severity");
    expect(stderrOutput).toContain("extreme");

    stderrSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 7. Duplicate names — both are loaded (no dedup at this layer)
  // -------------------------------------------------------------------------
  it("should load rules with duplicate names without deduplication", () => {
    const rules = [
      { name: "My Rule", pattern: "abc_[0-9]+", severity: "high" },
      { name: "My Rule", pattern: "xyz_[0-9]+", severity: "medium" },
    ];
    const filePath = writeRulesFile(tempDir, rules);

    const result = loadCustomRules(filePath);

    expect(result).toHaveLength(2);
    expect(result[0].name).toBe("My Rule");
    expect(result[1].name).toBe("My Rule");
    // They should have different patterns
    expect(result[0].pattern.source).toBe("abc_[0-9]+");
    expect(result[1].pattern.source).toBe("xyz_[0-9]+");
  });

  // -------------------------------------------------------------------------
  // 8. Missing required fields — skip with warning
  // -------------------------------------------------------------------------
  it("should skip rules with missing required fields", () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    const rules = [
      { name: "No Pattern", severity: "high" },
      { pattern: "no_name_[0-9]+", severity: "high" },
      { name: "No Severity", pattern: "test_[0-9]+" },
      { name: "All Good", pattern: "good_[0-9]+", severity: "low" },
    ];
    const filePath = writeRulesFile(tempDir, rules);

    const result = loadCustomRules(filePath);

    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("All Good");

    stderrSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 9. Non-array JSON — return empty with warning
  // -------------------------------------------------------------------------
  it("should return empty and warn when file contains a non-array JSON value", () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    const filePath = join(tempDir, "rules.json");
    writeFileSync(filePath, '{"not": "an array"}', "utf-8");

    const result = loadCustomRules(filePath);

    expect(result).toEqual([]);

    const stderrOutput = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
    expect(stderrOutput).toContain("must contain a JSON array");

    stderrSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 10. Malformed JSON — return empty with warning
  // -------------------------------------------------------------------------
  it("should return empty and warn when file contains malformed JSON", () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    const filePath = join(tempDir, "rules.json");
    writeFileSync(filePath, "this is not valid json {{{", "utf-8");

    const result = loadCustomRules(filePath);

    expect(result).toEqual([]);

    const stderrOutput = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
    expect(stderrOutput).toContain("Failed to parse");

    stderrSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 11. Compiled regex patterns actually work
  // -------------------------------------------------------------------------
  it("should compile regex patterns that correctly match target strings", () => {
    const rules = [
      { name: "Internal API Key", pattern: "MYCO-[A-Z0-9]{32}", severity: "high" },
    ];
    const filePath = writeRulesFile(tempDir, rules);

    const result = loadCustomRules(filePath);

    expect(result).toHaveLength(1);
    const pattern = result[0].pattern;

    // Should match
    expect(pattern.test("MYCO-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")).toBe(true);

    // Reset lastIndex since it's a global regex
    pattern.lastIndex = 0;

    // Should NOT match (too short)
    expect(pattern.test("MYCO-ABC")).toBe(false);
  });

  // -------------------------------------------------------------------------
  // 12. Rule with empty name — skip with warning
  // -------------------------------------------------------------------------
  it("should skip rules with empty string name", () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    const rules = [
      { name: "", pattern: "test_[0-9]+", severity: "high" },
      { name: "Valid", pattern: "ok_[0-9]+", severity: "low" },
    ];
    const filePath = writeRulesFile(tempDir, rules);

    const result = loadCustomRules(filePath);

    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("Valid");

    stderrSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 13. Rule with empty pattern — skip with warning
  // -------------------------------------------------------------------------
  it("should skip rules with empty string pattern", () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    const rules = [
      { name: "Empty Pattern", pattern: "", severity: "high" },
      { name: "Valid", pattern: "ok_[0-9]+", severity: "low" },
    ];
    const filePath = writeRulesFile(tempDir, rules);

    const result = loadCustomRules(filePath);

    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("Valid");

    stderrSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 14. Non-object entries in the array — skip with warning
  // -------------------------------------------------------------------------
  it("should skip non-object entries in the rules array", () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    const rules = [
      "just a string",
      42,
      null,
      { name: "Good Rule", pattern: "good_[0-9]+", severity: "high" },
    ];
    const filePath = writeRulesFile(tempDir, rules);

    const result = loadCustomRules(filePath);

    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("Good Rule");

    stderrSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 15. Default path — uses ~/.config/shhh/rules.json when no arg given
  // -------------------------------------------------------------------------
  it("should return empty array when no argument is given and default file does not exist", () => {
    // Calling with no argument should attempt the default path
    // Since the test environment likely does not have ~/.config/shhh/rules.json,
    // it should gracefully return an empty array
    const result = loadCustomRules();

    // We can only assert it returns an array (empty if file doesn't exist)
    expect(Array.isArray(result)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Integration: custom rules work with detectSecrets
// ---------------------------------------------------------------------------
describe("Custom rules integration with detectSecrets", () => {
  it("should detect secrets matching custom rules when passed to detectSecrets", async () => {
    const { detectSecrets } = await import("../src/detector");

    const customRules = [
      {
        name: "Internal API Key",
        severity: "high" as const,
        pattern: /MYCO-[A-Z0-9]{32}/g,
      },
    ];

    const content = "config: MYCO-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
    const findings = detectSecrets(content, "/tmp/test.json", "claude", customRules);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const customFinding = findings.find((f) => f.secretType === "Internal API Key");
    expect(customFinding).toBeDefined();
    expect(customFinding!.severity).toBe("high");
  });

  it("should still detect built-in patterns alongside custom rules", async () => {
    const { detectSecrets } = await import("../src/detector");

    const customRules = [
      {
        name: "Custom Token",
        severity: "medium" as const,
        pattern: /CUSTOM_[A-Z]{20}/g,
      },
    ];

    const content = "key=AKIAIOSFODNN7EXAMPLE token=CUSTOM_ABCDEFGHIJKLMNOPQRST";
    const findings = detectSecrets(content, "/tmp/test.json", "claude", customRules);

    const awsFinding = findings.find((f) => f.secretType.includes("AWS"));
    const customFinding = findings.find((f) => f.secretType === "Custom Token");

    expect(awsFinding).toBeDefined();
    expect(customFinding).toBeDefined();
  });

  it("should not break existing behavior when customRules is undefined", async () => {
    const { detectSecrets } = await import("../src/detector");

    const content = "AKIAIOSFODNN7EXAMPLE";
    const findings = detectSecrets(content, "/tmp/test.json", "claude", undefined);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const awsFinding = findings.find((f) => f.secretType.includes("AWS"));
    expect(awsFinding).toBeDefined();
  });

  it("should handle custom rules with global flag reset between files", async () => {
    const { detectSecrets } = await import("../src/detector");

    const customRules = [
      {
        name: "Custom Token",
        severity: "high" as const,
        pattern: /CUSTOM_[A-Z]{10}/g,
      },
    ];

    // Run detection on two different contents to verify lastIndex is reset
    const content1 = "token=CUSTOM_ABCDEFGHIJ";
    const findings1 = detectSecrets(content1, "/tmp/file1.json", "claude", customRules);
    expect(findings1.some((f) => f.secretType === "Custom Token")).toBe(true);

    const content2 = "other=CUSTOM_KLMNOPQRST";
    const findings2 = detectSecrets(content2, "/tmp/file2.json", "claude", customRules);
    expect(findings2.some((f) => f.secretType === "Custom Token")).toBe(true);
  });
});
