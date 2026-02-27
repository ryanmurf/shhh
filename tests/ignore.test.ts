import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir, homedir } from "node:os";
import { loadIgnoreRules, shouldIgnore, shouldIgnoreFile } from "../src/ignore";
import type { IgnoreRules } from "../src/ignore";
import type { Finding, Platform } from "../src/types";

/**
 * Helper to create a minimal Finding for testing.
 */
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "test-id-001",
    secretType: "GitHub Personal Access Token",
    severity: "high",
    match: "ghp_****ghij",
    filePath: "/home/user/.claude/sessions/abc.jsonl",
    line: 42,
    column: 10,
    platform: "claude",
    context: '..."token": "ghp_****ghij"...',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// shouldIgnore — literal string matching
// ---------------------------------------------------------------------------
describe("shouldIgnore: literal string rules", () => {
  it("should ignore a finding when the literal appears in the match field", () => {
    const rules: IgnoreRules = {
      literals: ["ghp_"],
      types: [],
      fileGlobs: [],
      platforms: [],
    };
    const finding = makeFinding({ match: "ghp_****ghij" });
    expect(shouldIgnore(finding, rules)).toBe(true);
  });

  it("should ignore a finding when the literal appears in the context field", () => {
    const rules: IgnoreRules = {
      literals: ["EXAMPLE_TOKEN"],
      types: [],
      fileGlobs: [],
      platforms: [],
    };
    const finding = makeFinding({
      match: "ghp_****ghij",
      context: 'using EXAMPLE_TOKEN for testing "ghp_****ghij"',
    });
    expect(shouldIgnore(finding, rules)).toBe(true);
  });

  it("should NOT ignore a finding when the literal does not match", () => {
    const rules: IgnoreRules = {
      literals: ["SOME_OTHER_STRING"],
      types: [],
      fileGlobs: [],
      platforms: [],
    };
    const finding = makeFinding();
    expect(shouldIgnore(finding, rules)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// shouldIgnore — type prefix matching
// ---------------------------------------------------------------------------
describe("shouldIgnore: type prefix rules", () => {
  it("should ignore findings whose secretType starts with a type: rule", () => {
    const rules: IgnoreRules = {
      literals: [],
      types: ["High-Entropy"],
      fileGlobs: [],
      platforms: [],
    };
    const finding = makeFinding({
      secretType: "High-Entropy String (entropy: 5.12)",
    });
    expect(shouldIgnore(finding, rules)).toBe(true);
  });

  it("should perform case-insensitive type matching", () => {
    const rules: IgnoreRules = {
      literals: [],
      types: ["high-entropy"],
      fileGlobs: [],
      platforms: [],
    };
    const finding = makeFinding({
      secretType: "High-Entropy String (entropy: 5.12)",
    });
    expect(shouldIgnore(finding, rules)).toBe(true);
  });

  it("should NOT ignore findings with a non-matching type prefix", () => {
    const rules: IgnoreRules = {
      literals: [],
      types: ["AWS"],
      fileGlobs: [],
      platforms: [],
    };
    const finding = makeFinding({ secretType: "GitHub Personal Access Token" });
    expect(shouldIgnore(finding, rules)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// shouldIgnore — file glob matching
// ---------------------------------------------------------------------------
describe("shouldIgnore: file glob rules", () => {
  it("should ignore findings in files matching a file glob", () => {
    const rules: IgnoreRules = {
      literals: [],
      types: [],
      fileGlobs: ["**/archived_sessions/**"],
      platforms: [],
    };
    const finding = makeFinding({
      filePath: "/home/user/.claude/archived_sessions/old.jsonl",
    });
    expect(shouldIgnore(finding, rules)).toBe(true);
  });

  it("should NOT ignore findings in files not matching any glob", () => {
    const rules: IgnoreRules = {
      literals: [],
      types: [],
      fileGlobs: ["**/archived_sessions/**"],
      platforms: [],
    };
    const finding = makeFinding({
      filePath: "/home/user/.claude/sessions/current.jsonl",
    });
    expect(shouldIgnore(finding, rules)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// shouldIgnore — platform matching
// ---------------------------------------------------------------------------
describe("shouldIgnore: platform rules", () => {
  it("should ignore findings from a matching platform", () => {
    const rules: IgnoreRules = {
      literals: [],
      types: [],
      fileGlobs: [],
      platforms: ["copilot"],
    };
    const finding = makeFinding({ platform: "copilot" });
    expect(shouldIgnore(finding, rules)).toBe(true);
  });

  it("should perform case-insensitive platform matching", () => {
    const rules: IgnoreRules = {
      literals: [],
      types: [],
      fileGlobs: [],
      platforms: ["Copilot"],
    };
    const finding = makeFinding({ platform: "copilot" });
    expect(shouldIgnore(finding, rules)).toBe(true);
  });

  it("should NOT ignore findings from a non-matching platform", () => {
    const rules: IgnoreRules = {
      literals: [],
      types: [],
      fileGlobs: [],
      platforms: ["copilot"],
    };
    const finding = makeFinding({ platform: "claude" });
    expect(shouldIgnore(finding, rules)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// shouldIgnoreFile — file-level filtering before scanning
// ---------------------------------------------------------------------------
describe("shouldIgnoreFile", () => {
  it("should return true for a file matching a glob", () => {
    const rules: IgnoreRules = {
      literals: [],
      types: [],
      fileGlobs: ["**/test-fixtures/**"],
      platforms: [],
    };
    expect(
      shouldIgnoreFile("/home/user/test-fixtures/session.json", rules),
    ).toBe(true);
  });

  it("should return false for a file not matching any glob", () => {
    const rules: IgnoreRules = {
      literals: [],
      types: [],
      fileGlobs: ["**/test-fixtures/**"],
      platforms: [],
    };
    expect(
      shouldIgnoreFile("/home/user/.claude/sessions/session.json", rules),
    ).toBe(false);
  });

  it("should handle multiple file globs", () => {
    const rules: IgnoreRules = {
      literals: [],
      types: [],
      fileGlobs: ["**/archived/**", "**/*.test.json"],
      platforms: [],
    };
    expect(
      shouldIgnoreFile("/data/something.test.json", rules),
    ).toBe(true);
    expect(
      shouldIgnoreFile("/data/archived/old.jsonl", rules),
    ).toBe(true);
    expect(
      shouldIgnoreFile("/data/live/current.jsonl", rules),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// loadIgnoreRules — file loading and parsing
// ---------------------------------------------------------------------------
describe("loadIgnoreRules", () => {
  const testDir = join(tmpdir(), `shhh-ignore-test-${process.pid}`);

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should return empty rules when no .shhhignore file exists", () => {
    const rules = loadIgnoreRules(testDir);
    expect(rules.literals).toEqual([]);
    expect(rules.types).toEqual([]);
    expect(rules.fileGlobs).toEqual([]);
    expect(rules.platforms).toEqual([]);
  });

  it("should parse a local .shhhignore with all rule types", () => {
    const content = [
      "# This is a comment",
      "",
      "ghp_abc123exampleToken",
      "type:High-Entropy",
      "file:**/archived/**",
      "platform:copilot",
      "",
      "# Another comment",
      "AKIAIOSFODNN7EXAMPLE",
    ].join("\n");

    writeFileSync(join(testDir, ".shhhignore"), content, "utf-8");
    const rules = loadIgnoreRules(testDir);

    expect(rules.literals).toEqual([
      "ghp_abc123exampleToken",
      "AKIAIOSFODNN7EXAMPLE",
    ]);
    expect(rules.types).toEqual(["High-Entropy"]);
    expect(rules.fileGlobs).toEqual(["**/archived/**"]);
    expect(rules.platforms).toEqual(["copilot"]);
  });

  it("should skip blank lines and comment lines", () => {
    const content = [
      "# comment 1",
      "   # indented comment",
      "",
      "   ",
      "literal_value",
    ].join("\n");

    writeFileSync(join(testDir, ".shhhignore"), content, "utf-8");
    const rules = loadIgnoreRules(testDir);

    expect(rules.literals).toEqual(["literal_value"]);
    expect(rules.types).toEqual([]);
    expect(rules.fileGlobs).toEqual([]);
    expect(rules.platforms).toEqual([]);
  });

  it("should handle a file with only comments and blank lines", () => {
    const content = [
      "# comment only",
      "",
      "# another comment",
    ].join("\n");

    writeFileSync(join(testDir, ".shhhignore"), content, "utf-8");
    const rules = loadIgnoreRules(testDir);

    expect(rules.literals).toEqual([]);
    expect(rules.types).toEqual([]);
    expect(rules.fileGlobs).toEqual([]);
    expect(rules.platforms).toEqual([]);
  });

  it("should trim whitespace around rule values", () => {
    const content = [
      "type:  High-Entropy  ",
      "file:  **/test/**  ",
      "platform:  copilot  ",
      "  literal_with_spaces  ",
    ].join("\n");

    writeFileSync(join(testDir, ".shhhignore"), content, "utf-8");
    const rules = loadIgnoreRules(testDir);

    expect(rules.types).toEqual(["High-Entropy"]);
    expect(rules.fileGlobs).toEqual(["**/test/**"]);
    expect(rules.platforms).toEqual(["copilot"]);
    expect(rules.literals).toEqual(["literal_with_spaces"]);
  });

  it("should ignore rules with empty values after the prefix", () => {
    const content = [
      "type:",
      "file:",
      "platform:",
    ].join("\n");

    writeFileSync(join(testDir, ".shhhignore"), content, "utf-8");
    const rules = loadIgnoreRules(testDir);

    expect(rules.types).toEqual([]);
    expect(rules.fileGlobs).toEqual([]);
    expect(rules.platforms).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Edge cases in .shhhignore parsing (BUG-015)
// ---------------------------------------------------------------------------
describe("loadIgnoreRules: malformed lines and edge cases (BUG-015)", () => {
  const testDir = join(tmpdir(), `shhh-ignore-edge-${process.pid}`);

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should handle a .shhhignore file with Windows-style CRLF line endings", () => {
    const content = "type:AWS\r\nfile:**/test/**\r\nplatform:copilot\r\nliteral_value\r\n";
    writeFileSync(join(testDir, ".shhhignore"), content, "utf-8");
    const rules = loadIgnoreRules(testDir);

    expect(rules.types).toEqual(["AWS"]);
    expect(rules.fileGlobs).toEqual(["**/test/**"]);
    expect(rules.platforms).toEqual(["copilot"]);
    expect(rules.literals).toEqual(["literal_value"]);
  });

  it("should handle lines with only the prefix and no value gracefully", () => {
    const content = "type:\nfile:\nplatform:\n";
    writeFileSync(join(testDir, ".shhhignore"), content, "utf-8");
    const rules = loadIgnoreRules(testDir);

    expect(rules.types).toEqual([]);
    expect(rules.fileGlobs).toEqual([]);
    expect(rules.platforms).toEqual([]);
  });

  it("should not crash on a binary .shhhignore file", () => {
    const binaryContent = Buffer.from([0x00, 0x01, 0xFF, 0xFE, 0x0A, 0x48, 0x65, 0x6C, 0x6C, 0x6F]);
    writeFileSync(join(testDir, ".shhhignore"), binaryContent);

    // Should not throw
    expect(() => loadIgnoreRules(testDir)).not.toThrow();
  });

  it("should treat lines starting with 'type:' literally when value contains colons", () => {
    const content = "type:type:nested:value\n";
    writeFileSync(join(testDir, ".shhhignore"), content, "utf-8");
    const rules = loadIgnoreRules(testDir);

    // The value after "type:" should be "type:nested:value"
    expect(rules.types).toEqual(["type:nested:value"]);
  });
});

// ---------------------------------------------------------------------------
// Combined / integration-style tests
// ---------------------------------------------------------------------------
describe("shouldIgnore: combined rules", () => {
  it("should ignore if ANY rule matches (logical OR across rule types)", () => {
    const rules: IgnoreRules = {
      literals: ["nonexistent"],
      types: ["AWS"],
      fileGlobs: [],
      platforms: [],
    };
    // The type matches even though the literal does not
    const finding = makeFinding({ secretType: "AWS Access Key ID" });
    expect(shouldIgnore(finding, rules)).toBe(true);
  });

  it("should not ignore when no rules match across any category", () => {
    const rules: IgnoreRules = {
      literals: ["totally_unrelated"],
      types: ["Slack"],
      fileGlobs: ["**/something_else/**"],
      platforms: ["codex"],
    };
    const finding = makeFinding({
      secretType: "GitHub Personal Access Token",
      platform: "claude",
      filePath: "/home/user/.claude/sessions/abc.jsonl",
      match: "ghp_****ghij",
      context: 'token "ghp_****ghij"',
    });
    expect(shouldIgnore(finding, rules)).toBe(false);
  });
});
