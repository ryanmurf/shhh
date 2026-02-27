import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { discoverSessionFiles } from "../src/discovery";
import type { SessionFile, Platform } from "../src/types";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

/**
 * Tests for the session file discovery module.
 *
 * We expect discoverSessionFiles to have a signature like:
 *   discoverSessionFiles(options?: { platform?: Platform }): SessionFile[]
 *
 * It should search known directories:
 *   - Claude Code:   ~/.claude/
 *   - OpenAI Codex:  ~/.codex/
 *   - GitHub Copilot: ~/.config/github-copilot/
 */

describe("discoverSessionFiles", () => {
  // -------------------------------------------------------------------
  // Return shape
  // -------------------------------------------------------------------
  it("should return an array", () => {
    const result = discoverSessionFiles();
    expect(Array.isArray(result)).toBe(true);
  });

  it("should return objects with platform and filePath properties", () => {
    const results = discoverSessionFiles();
    for (const file of results) {
      expect(file).toHaveProperty("platform");
      expect(file).toHaveProperty("filePath");
      expect(typeof file.platform).toBe("string");
      expect(typeof file.filePath).toBe("string");
    }
  });

  it("each returned platform should be one of the known platforms", () => {
    const validPlatforms: Platform[] = ["claude", "codex", "copilot"];
    const results = discoverSessionFiles();
    for (const file of results) {
      expect(validPlatforms).toContain(file.platform);
    }
  });

  it("each returned filePath should be an absolute path", () => {
    const results = discoverSessionFiles();
    for (const file of results) {
      expect(path.isAbsolute(file.filePath)).toBe(true);
    }
  });

  // -------------------------------------------------------------------
  // Platform filtering
  // -------------------------------------------------------------------
  it("should accept a platform filter and return only that platform", () => {
    const results = discoverSessionFiles({ platform: "claude" });
    for (const file of results) {
      expect(file.platform).toBe("claude");
    }
  });

  it("should filter for codex platform", () => {
    const results = discoverSessionFiles({ platform: "codex" });
    for (const file of results) {
      expect(file.platform).toBe("codex");
    }
  });

  it("should filter for copilot platform", () => {
    const results = discoverSessionFiles({ platform: "copilot" });
    for (const file of results) {
      expect(file.platform).toBe("copilot");
    }
  });

  it("should return a subset when filtering vs. no filter", () => {
    const all = discoverSessionFiles();
    const claudeOnly = discoverSessionFiles({ platform: "claude" });
    // claude-only should be <= total (could be equal if only claude files exist)
    expect(claudeOnly.length).toBeLessThanOrEqual(all.length);
  });

  // -------------------------------------------------------------------
  // Graceful handling of missing directories
  // -------------------------------------------------------------------
  it("should not throw when session directories do not exist", () => {
    // Even on a system without any AI assistant installed, this should
    // return an empty array rather than crash.
    expect(() => discoverSessionFiles()).not.toThrow();
  });

  it("should return an empty array when no session files are found", () => {
    // With a platform that likely has no files in test environment
    const results = discoverSessionFiles({ platform: "copilot" });
    // We can't guarantee it's empty (CI might have copilot), but it
    // should at least not crash and return an array
    expect(Array.isArray(results)).toBe(true);
  });

  // -------------------------------------------------------------------
  // Robustness
  // -------------------------------------------------------------------
  it("should not return duplicate file paths", () => {
    const results = discoverSessionFiles();
    const paths = results.map((f) => f.filePath);
    const uniquePaths = new Set(paths);
    expect(paths.length).toBe(uniquePaths.size);
  });

  it("should handle being called multiple times without side effects", () => {
    const first = discoverSessionFiles();
    const second = discoverSessionFiles();
    // Both calls should return the same set of files
    expect(first.length).toBe(second.length);
    for (let i = 0; i < first.length; i++) {
      expect(first[i].filePath).toBe(second[i].filePath);
      expect(first[i].platform).toBe(second[i].platform);
    }
  });
});

// ---------------------------------------------------------------------------
// Integration-style test with temp directory
// ---------------------------------------------------------------------------
describe("discoverSessionFiles with real files", () => {
  let tmpDir: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "shhh-test-"));
    originalHome = process.env.HOME;
    // Point HOME to our temp dir so discovery looks there
    process.env.HOME = tmpDir;
  });

  afterEach(() => {
    if (originalHome !== undefined) {
      process.env.HOME = originalHome;
    }
    // Clean up temp dir
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should discover Claude session files when .claude directory exists", () => {
    // Create a fake Claude session directory with a file
    const claudeDir = path.join(tmpDir, ".claude");
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, "session.json"),
      '{"messages": []}'
    );

    const results = discoverSessionFiles({ platform: "claude" });
    // Should find at least the file we created
    const claudeFiles = results.filter((f) => f.platform === "claude");
    expect(claudeFiles.length).toBeGreaterThanOrEqual(1);
  });

  it("should return empty array when HOME points to a dir with no session dirs", () => {
    // tmpDir exists but has no .claude, .codex, or .config/github-copilot
    const results = discoverSessionFiles();
    expect(results).toEqual([]);
  });

  // -----------------------------------------------------------------------
  // BUG-014: Variant directory matching must require a separator character
  // e.g. .claudebot should NOT match, but .claude-dev, .claude_work,
  // .claude.bak SHOULD match.
  // -----------------------------------------------------------------------
  it("should NOT match a directory like .claudebot (no separator after prefix)", () => {
    const bogusDir = path.join(tmpDir, ".claudebot");
    fs.mkdirSync(bogusDir, { recursive: true });
    fs.writeFileSync(path.join(bogusDir, "data.json"), '{}');

    const results = discoverSessionFiles({ platform: "claude" });
    const bogusFiles = results.filter((f) =>
      f.filePath.includes(".claudebot")
    );
    expect(bogusFiles).toHaveLength(0);
  });

  it("should NOT match a directory like .codextra (no separator after prefix)", () => {
    const bogusDir = path.join(tmpDir, ".codextra");
    fs.mkdirSync(bogusDir, { recursive: true });
    fs.writeFileSync(path.join(bogusDir, "data.jsonl"), '{}');

    const results = discoverSessionFiles({ platform: "codex" });
    const bogusFiles = results.filter((f) =>
      f.filePath.includes(".codextra")
    );
    expect(bogusFiles).toHaveLength(0);
  });

  it("should match variant directories with valid separators (-, ., _)", () => {
    const variants = [".claude-dev", ".claude_work", ".claude.bak"];
    for (const variant of variants) {
      const dir = path.join(tmpDir, variant);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, "session.json"), '{}');
    }

    const results = discoverSessionFiles({ platform: "claude" });
    for (const variant of variants) {
      const found = results.some((f) => f.filePath.includes(variant));
      expect(found).toBe(true);
    }
  });

  it("should discover files in the exact prefix directory (.claude)", () => {
    const dir = path.join(tmpDir, ".claude");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "session.jsonl"), '{}');

    const results = discoverSessionFiles({ platform: "claude" });
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results.some((f) => f.filePath.includes(".claude/session.jsonl"))).toBe(true);
  });
});
