import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { redactFindings, buildPlaceholder } from "../src/redactor";
import { detectSecrets } from "../src/detector";
import type { Finding } from "../src/types";

/**
 * Helper to create a Finding object with sensible defaults.
 * The `match` field mirrors how the detector redacts: "ghp_****ghij".
 */
function makeFinding(overrides: Partial<Finding> & { filePath: string; line: number; column: number }): Finding {
  return {
    id: "test-id-" + Math.random().toString(36).slice(2),
    secretType: "GitHub Personal Access Token",
    severity: "high",
    match: "ghp_****ghij",
    platform: "claude",
    context: "...token: ghp_****ghij...",
    ...overrides,
  };
}

describe("redactor module", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "shhh-redactor-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // -----------------------------------------------------------------------
  // 1. Dry run produces correct counts without modifying files
  // -----------------------------------------------------------------------
  describe("dry run mode", () => {
    it("should produce correct counts without modifying files", () => {
      const filePath = path.join(tmpDir, "session.json");
      const content = 'token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';
      fs.writeFileSync(filePath, content);

      const finding = makeFinding({ filePath, line: 1, column: 8 });

      const result = redactFindings([finding], { dryRun: true });

      expect(result.filesModified).toBe(1);
      expect(result.secretsRedacted).toBe(1);
      expect(result.errors).toEqual([]);

      // File should NOT be modified
      const afterContent = fs.readFileSync(filePath, "utf-8");
      expect(afterContent).toBe(content);
    });

    it("should not create backup files in dry run mode", () => {
      const filePath = path.join(tmpDir, "session.json");
      fs.writeFileSync(filePath, "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");

      const finding = makeFinding({ filePath, line: 1, column: 8 });

      redactFindings([finding], { dryRun: true, backup: true });

      expect(fs.existsSync(filePath + ".bak")).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // 2. Redaction replaces secret at correct position
  // -----------------------------------------------------------------------
  describe("basic redaction", () => {
    it("should replace the secret at the correct position", () => {
      const filePath = path.join(tmpDir, "session.json");
      const secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
      const content = `token: ${secret}`;
      fs.writeFileSync(filePath, content);

      const finding = makeFinding({ filePath, line: 1, column: 8 });

      const result = redactFindings([finding], { backup: false });

      expect(result.secretsRedacted).toBe(1);
      expect(result.filesModified).toBe(1);

      const modified = fs.readFileSync(filePath, "utf-8");
      expect(modified).not.toContain(secret);
      expect(modified).toContain("[REDACTED:");
      expect(modified).toContain("token: [REDACTED:");
    });
  });

  // -----------------------------------------------------------------------
  // 3. Backup files are created when backup=true
  // -----------------------------------------------------------------------
  describe("backup creation", () => {
    it("should create .bak files when backup is true (default)", () => {
      const filePath = path.join(tmpDir, "session.json");
      const content = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
      fs.writeFileSync(filePath, content);

      const finding = makeFinding({ filePath, line: 1, column: 8 });

      redactFindings([finding]); // backup defaults to true

      expect(fs.existsSync(filePath + ".bak")).toBe(true);
      const bakContent = fs.readFileSync(filePath + ".bak", "utf-8");
      expect(bakContent).toBe(content);
    });
  });

  // -----------------------------------------------------------------------
  // 4. No backup files when backup=false
  // -----------------------------------------------------------------------
  describe("no backup mode", () => {
    it("should not create .bak files when backup is false", () => {
      const filePath = path.join(tmpDir, "session.json");
      fs.writeFileSync(filePath, "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");

      const finding = makeFinding({ filePath, line: 1, column: 8 });

      redactFindings([finding], { backup: false });

      expect(fs.existsSync(filePath + ".bak")).toBe(false);
      // File should still be modified
      const modified = fs.readFileSync(filePath, "utf-8");
      expect(modified).toContain("[REDACTED:");
    });
  });

  // -----------------------------------------------------------------------
  // 5. Handles findings in JSONL files correctly
  // -----------------------------------------------------------------------
  describe("JSONL file handling", () => {
    it("should redact a secret on the correct line in a JSONL file", () => {
      const filePath = path.join(tmpDir, "session.jsonl");
      const lines = [
        JSON.stringify({ role: "user", content: "Hello" }),
        JSON.stringify({ role: "assistant", content: "Hi there" }),
        JSON.stringify({ role: "user", content: "my token is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" }),
        JSON.stringify({ role: "assistant", content: "I see" }),
      ];
      fs.writeFileSync(filePath, lines.join("\n"));

      // The secret is on line 3; find the column
      const line3 = lines[2];
      const secretIdx = line3.indexOf("ghp_");
      const column = secretIdx + 1; // 1-based

      const finding = makeFinding({ filePath, line: 3, column });

      const result = redactFindings([finding], { backup: false });

      expect(result.secretsRedacted).toBe(1);

      const modified = fs.readFileSync(filePath, "utf-8");
      const modifiedLines = modified.split("\n");

      // Lines 1, 2, 4 should be unchanged
      expect(modifiedLines[0]).toBe(lines[0]);
      expect(modifiedLines[1]).toBe(lines[1]);
      expect(modifiedLines[3]).toBe(lines[3]);

      // Line 3 should have the redaction
      expect(modifiedLines[2]).toContain("[REDACTED:");
      expect(modifiedLines[2]).not.toContain("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
    });
  });

  // -----------------------------------------------------------------------
  // 6. Handles multiple findings in the same file
  // -----------------------------------------------------------------------
  describe("multiple findings in same file", () => {
    it("should redact all secrets in a single file", () => {
      const filePath = path.join(tmpDir, "multi.json");
      const line1 = "token1: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
      const line2 = "safe line here";
      const line3 = "token2: ghp_ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrq";
      fs.writeFileSync(filePath, [line1, line2, line3].join("\n"));

      const finding1 = makeFinding({ filePath, line: 1, column: 9 });
      const finding2 = makeFinding({
        filePath,
        line: 3,
        column: 9,
        match: "ghp_****tsrq",
      });

      const result = redactFindings([finding1, finding2], { backup: false });

      expect(result.secretsRedacted).toBe(2);
      expect(result.filesModified).toBe(1);

      const modified = fs.readFileSync(filePath, "utf-8");
      const modifiedLines = modified.split("\n");

      // Both lines should be redacted
      expect(modifiedLines[0]).toContain("[REDACTED:");
      expect(modifiedLines[1]).toBe(line2); // safe line unchanged
      expect(modifiedLines[2]).toContain("[REDACTED:");
    });
  });

  // -----------------------------------------------------------------------
  // 7. Handles multiple findings on the same line
  // -----------------------------------------------------------------------
  describe("multiple findings on same line", () => {
    it("should redact multiple secrets on a single line", () => {
      const filePath = path.join(tmpDir, "sameline.json");
      const secret1 = "AKIAIOSFODNN7EXAMPLE";
      const secret2 = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
      const content = `keys: ${secret1} and ${secret2}`;
      fs.writeFileSync(filePath, content);

      const col1 = content.indexOf(secret1) + 1; // 1-based
      const col2 = content.indexOf(secret2) + 1; // 1-based

      const finding1 = makeFinding({
        filePath,
        line: 1,
        column: col1,
        secretType: "AWS Access Key ID",
        match: "AKIA****MPLE",
      });
      const finding2 = makeFinding({
        filePath,
        line: 1,
        column: col2,
        match: "ghp_****ghij",
      });

      const result = redactFindings([finding1, finding2], { backup: false });

      expect(result.secretsRedacted).toBe(2);

      const modified = fs.readFileSync(filePath, "utf-8");
      expect(modified).not.toContain(secret1);
      expect(modified).not.toContain(secret2);
      // Should have two REDACTED placeholders
      const matches = modified.match(/\[REDACTED:/g);
      expect(matches).not.toBeNull();
      expect(matches!.length).toBe(2);
    });
  });

  // -----------------------------------------------------------------------
  // 8. Error handling for missing files
  // -----------------------------------------------------------------------
  describe("error handling for missing files", () => {
    it("should report an error for a file that does not exist", () => {
      const missingFile = path.join(tmpDir, "nonexistent.json");
      const finding = makeFinding({
        filePath: missingFile,
        line: 1,
        column: 1,
      });

      const result = redactFindings([finding], { backup: false });

      expect(result.filesModified).toBe(0);
      expect(result.secretsRedacted).toBe(0);
      expect(result.errors.length).toBeGreaterThanOrEqual(1);
      expect(result.errors[0]).toContain("File not found");
    });
  });

  // -----------------------------------------------------------------------
  // 9. Redaction placeholder format is correct
  // -----------------------------------------------------------------------
  describe("placeholder format", () => {
    it("should produce [REDACTED:secret_type:first4chars] format", () => {
      const finding = makeFinding({
        filePath: "/tmp/test",
        line: 1,
        column: 1,
        secretType: "GitHub Personal Access Token",
        match: "ghp_****ghij",
      });

      const placeholder = buildPlaceholder(finding);

      expect(placeholder).toBe("[REDACTED:GitHub_Personal_Access_Token:ghp_]");
    });

    it("should handle secret types with spaces replaced by underscores", () => {
      const finding = makeFinding({
        filePath: "/tmp/test",
        line: 1,
        column: 1,
        secretType: "AWS Access Key ID",
        match: "AKIA****MPLE",
      });

      const placeholder = buildPlaceholder(finding);

      expect(placeholder).toBe("[REDACTED:AWS_Access_Key_ID:AKIA]");
    });

    it("should use the prefix before asterisks for the first4chars", () => {
      const finding = makeFinding({
        filePath: "/tmp/test",
        line: 1,
        column: 1,
        secretType: "Slack Bot Token",
        match: "xoxb****UvWx",
      });

      const placeholder = buildPlaceholder(finding);

      expect(placeholder).toBe("[REDACTED:Slack_Bot_Token:xoxb]");
    });

    it("should use actual redacted content in the modified file", () => {
      const filePath = path.join(tmpDir, "placeholder.json");
      const content = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
      fs.writeFileSync(filePath, content);

      const finding = makeFinding({ filePath, line: 1, column: 8 });

      redactFindings([finding], { backup: false });

      const modified = fs.readFileSync(filePath, "utf-8");
      expect(modified).toContain("[REDACTED:GitHub_Personal_Access_Token:ghp_]");
    });
  });

  // -----------------------------------------------------------------------
  // 10. Empty findings array returns zero counts
  // -----------------------------------------------------------------------
  describe("empty findings", () => {
    it("should return zero counts for an empty findings array", () => {
      const result = redactFindings([]);

      expect(result.filesModified).toBe(0);
      expect(result.secretsRedacted).toBe(0);
      expect(result.errors).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // 11. Findings from different files are handled
  // -----------------------------------------------------------------------
  describe("findings across different files", () => {
    it("should redact secrets in multiple different files", () => {
      const file1 = path.join(tmpDir, "file1.json");
      const file2 = path.join(tmpDir, "file2.json");

      fs.writeFileSync(file1, "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
      fs.writeFileSync(file2, "key: AKIAIOSFODNN7EXAMPLE");

      const finding1 = makeFinding({
        filePath: file1,
        line: 1,
        column: 8,
        match: "ghp_****ghij",
      });
      const finding2 = makeFinding({
        filePath: file2,
        line: 1,
        column: 6,
        secretType: "AWS Access Key ID",
        match: "AKIA****MPLE",
      });

      const result = redactFindings([finding1, finding2], { backup: false });

      expect(result.filesModified).toBe(2);
      expect(result.secretsRedacted).toBe(2);
      expect(result.errors).toEqual([]);

      // Verify both files were modified
      const mod1 = fs.readFileSync(file1, "utf-8");
      const mod2 = fs.readFileSync(file2, "utf-8");
      expect(mod1).toContain("[REDACTED:GitHub_Personal_Access_Token:ghp_]");
      expect(mod2).toContain("[REDACTED:AWS_Access_Key_ID:AKIA]");
    });
  });

  // -----------------------------------------------------------------------
  // 12. Column offset is respected (not just line)
  // -----------------------------------------------------------------------
  describe("column offset handling", () => {
    it("should redact based on column, not just line", () => {
      const filePath = path.join(tmpDir, "column.json");
      const prefix = "some-prefix: ";
      const secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
      const suffix = " more-text-here";
      const content = prefix + secret + suffix;
      fs.writeFileSync(filePath, content);

      const column = prefix.length + 1; // 1-based column

      const finding = makeFinding({ filePath, line: 1, column });

      const result = redactFindings([finding], { backup: false });

      expect(result.secretsRedacted).toBe(1);

      const modified = fs.readFileSync(filePath, "utf-8");

      // The prefix should be preserved
      expect(modified.startsWith("some-prefix: ")).toBe(true);
      // The suffix should be preserved
      expect(modified).toContain("more-text-here");
      // The secret should be replaced
      expect(modified).not.toContain(secret);
      expect(modified).toContain("[REDACTED:");
    });

    it("should handle a secret that starts mid-line after JSON structure", () => {
      const filePath = path.join(tmpDir, "mid-line.jsonl");
      const content = '{"key":"safe","token":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij","other":"val"}';
      fs.writeFileSync(filePath, content);

      const secretIdx = content.indexOf("ghp_");
      const column = secretIdx + 1; // 1-based

      const finding = makeFinding({ filePath, line: 1, column });

      const result = redactFindings([finding], { backup: false });

      expect(result.secretsRedacted).toBe(1);

      const modified = fs.readFileSync(filePath, "utf-8");
      expect(modified).not.toContain("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
      expect(modified).toContain("[REDACTED:");
      // The JSON structure around it should be preserved
      expect(modified).toContain('"key":"safe"');
      expect(modified).toContain('"other":"val"');
    });
  });

  // -----------------------------------------------------------------------
  // Additional edge cases
  // -----------------------------------------------------------------------
  describe("filterFn (interactive mode)", () => {
    it("should only redact findings accepted by the filter function", () => {
      const file1 = path.join(tmpDir, "filter1.json");
      const file2 = path.join(tmpDir, "filter2.json");

      fs.writeFileSync(file1, "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
      fs.writeFileSync(file2, "token: ghp_ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrq");

      const finding1 = makeFinding({ filePath: file1, line: 1, column: 8 });
      const finding2 = makeFinding({
        filePath: file2,
        line: 1,
        column: 8,
        match: "ghp_****tsrq",
      });

      // Only accept finding1
      const result = redactFindings([finding1, finding2], {
        backup: false,
        filterFn: (f) => f.filePath === file1,
      });

      expect(result.secretsRedacted).toBe(1);
      expect(result.filesModified).toBe(1);

      // file1 should be redacted, file2 should be untouched
      const mod1 = fs.readFileSync(file1, "utf-8");
      const mod2 = fs.readFileSync(file2, "utf-8");
      expect(mod1).toContain("[REDACTED:");
      expect(mod2).toContain("ghp_ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrq");
    });
  });

  describe("integration with detector", () => {
    it("should work end-to-end: detect then redact", () => {
      const filePath = path.join(tmpDir, "e2e.json");
      const content = 'my github token is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij please use it';
      fs.writeFileSync(filePath, content);

      // Detect secrets
      const findings = detectSecrets(content, filePath, "claude");
      expect(findings.length).toBeGreaterThanOrEqual(1);

      // Redact them
      const result = redactFindings(findings, { backup: false });

      expect(result.secretsRedacted).toBeGreaterThanOrEqual(1);

      const modified = fs.readFileSync(filePath, "utf-8");
      expect(modified).not.toContain("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
      expect(modified).toContain("[REDACTED:");
      // Context around it should be preserved
      expect(modified).toContain("my github token is ");
      expect(modified).toContain(" please use it");
    });
  });

  describe("line out of range", () => {
    it("should report error when finding line exceeds file length", () => {
      const filePath = path.join(tmpDir, "short.json");
      fs.writeFileSync(filePath, "just one line");

      const finding = makeFinding({ filePath, line: 5, column: 1 });

      const result = redactFindings([finding], { backup: false });

      expect(result.secretsRedacted).toBe(0);
      expect(result.errors.length).toBe(1);
      expect(result.errors[0]).toContain("out of range");
    });
  });

  // -----------------------------------------------------------------------
  // Column out of range
  // -----------------------------------------------------------------------
  describe("column out of range", () => {
    it("should report error when column exceeds line length", () => {
      const filePath = path.join(tmpDir, "colrange.json");
      fs.writeFileSync(filePath, "short");

      const finding = makeFinding({ filePath, line: 1, column: 100 });

      const result = redactFindings([finding], { backup: false });

      expect(result.secretsRedacted).toBe(0);
      expect(result.errors.length).toBe(1);
      expect(result.errors[0]).toContain("Could not locate secret");
    });
  });

  // -----------------------------------------------------------------------
  // Escaped JSON strings in JSONL files
  // -----------------------------------------------------------------------
  describe("escaped strings in JSONL", () => {
    it("should redact a secret in a JSON-encoded string with escaped quotes", () => {
      const filePath = path.join(tmpDir, "escaped.jsonl");
      const secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
      const content = `{"content":"token is ${secret} and \\"other\\" stuff"}`;
      fs.writeFileSync(filePath, content);

      const secretIdx = content.indexOf("ghp_");
      const column = secretIdx + 1;

      const finding = makeFinding({ filePath, line: 1, column });
      const result = redactFindings([finding], { backup: false });

      expect(result.secretsRedacted).toBe(1);
      const modified = fs.readFileSync(filePath, "utf-8");
      expect(modified).not.toContain(secret);
      expect(modified).toContain("[REDACTED:");
    });
  });

  // -----------------------------------------------------------------------
  // Multiple findings on same line processed in correct order
  // -----------------------------------------------------------------------
  describe("multiple findings on same line - order verification", () => {
    it("should process right-to-left to preserve column positions", () => {
      const filePath = path.join(tmpDir, "multiorder.json");
      const secret1 = "AKIAIOSFODNN7EXAMPLE";
      const secret2 = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
      // Deliberately put secret2 AFTER secret1 on the same line
      const content = `first: ${secret1} second: ${secret2}`;
      fs.writeFileSync(filePath, content);

      const col1 = content.indexOf(secret1) + 1;
      const col2 = content.indexOf(secret2) + 1;

      // Pass findings in ASCENDING column order (wrong order for processing)
      // redactFindings should sort them internally to descending
      const finding1 = makeFinding({
        filePath,
        line: 1,
        column: col1,
        secretType: "AWS Access Key ID",
        match: "AKIA****MPLE",
      });
      const finding2 = makeFinding({
        filePath,
        line: 1,
        column: col2,
        match: "ghp_****ghij",
      });

      const result = redactFindings([finding1, finding2], { backup: false });

      expect(result.secretsRedacted).toBe(2);
      expect(result.errors).toEqual([]);

      const modified = fs.readFileSync(filePath, "utf-8");
      expect(modified).not.toContain(secret1);
      expect(modified).not.toContain(secret2);
      // Both placeholders should be present
      const placeholderCount = (modified.match(/\[REDACTED:/g) || []).length;
      expect(placeholderCount).toBe(2);
      // Surrounding text preserved
      expect(modified).toContain("first: ");
      expect(modified).toContain(" second: ");
    });
  });
});
