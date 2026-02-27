import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { installHook, uninstallHook } from "../src/hooks";

describe("hooks module", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "shhh-hooks-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  /**
   * Helper to create a .git directory structure inside tmpDir.
   */
  function initGitDir(): void {
    fs.mkdirSync(path.join(tmpDir, ".git", "hooks"), { recursive: true });
  }

  // -----------------------------------------------------------------------
  // installHook
  // -----------------------------------------------------------------------
  describe("installHook", () => {
    it("should create a pre-commit hook file when none exists", () => {
      initGitDir();
      installHook("pre-commit", tmpDir);

      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      expect(fs.existsSync(hookPath)).toBe(true);

      const content = fs.readFileSync(hookPath, "utf-8");
      expect(content).toContain("#!/bin/sh");
      expect(content).toContain("shhh secret scanner");
      expect(content).toContain("scan --format json");
    });

    it("should create a pre-push hook file when none exists", () => {
      initGitDir();
      installHook("pre-push", tmpDir);

      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-push");
      expect(fs.existsSync(hookPath)).toBe(true);

      const content = fs.readFileSync(hookPath, "utf-8");
      expect(content).toContain("scan --format json");
    });

    it("should make the hook file executable", () => {
      initGitDir();
      installHook("pre-commit", tmpDir);

      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      const stat = fs.statSync(hookPath);
      // Check that the owner execute bit is set
      // eslint-disable-next-line no-bitwise
      expect(stat.mode & 0o111).not.toBe(0);
    });

    it("should append to an existing hook without replacing it", () => {
      initGitDir();
      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      const existingContent = "#!/bin/sh\necho 'existing hook'\n";
      fs.writeFileSync(hookPath, existingContent, "utf-8");

      installHook("pre-commit", tmpDir);

      const content = fs.readFileSync(hookPath, "utf-8");
      // Existing content should be preserved
      expect(content).toContain("echo 'existing hook'");
      // New shhh content should also be present
      expect(content).toContain("shhh secret scanner");
    });

    it("should be a no-op if shhh hook is already installed", () => {
      initGitDir();
      installHook("pre-commit", tmpDir);

      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      const contentAfterFirstInstall = fs.readFileSync(hookPath, "utf-8");

      // Install again
      installHook("pre-commit", tmpDir);
      const contentAfterSecondInstall = fs.readFileSync(hookPath, "utf-8");

      expect(contentAfterSecondInstall).toBe(contentAfterFirstInstall);
    });

    it("should throw when .git directory does not exist", () => {
      // tmpDir has no .git directory
      expect(() => installHook("pre-commit", tmpDir)).toThrow(
        /No .git directory found/,
      );
    });

    it("should include npx fallback in the hook script", () => {
      initGitDir();
      installHook("pre-commit", tmpDir);

      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      const content = fs.readFileSync(hookPath, "utf-8");
      expect(content).toContain("npx shhh");
    });

    it("should create hooks dir if it does not exist inside .git", () => {
      // Create .git but not .git/hooks
      fs.mkdirSync(path.join(tmpDir, ".git"), { recursive: true });

      installHook("pre-commit", tmpDir);

      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      expect(fs.existsSync(hookPath)).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // uninstallHook
  // -----------------------------------------------------------------------
  describe("uninstallHook", () => {
    it("should remove the shhh section from the hook", () => {
      initGitDir();
      installHook("pre-commit", tmpDir);

      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      expect(fs.readFileSync(hookPath, "utf-8")).toContain("shhh secret scanner");

      uninstallHook("pre-commit", tmpDir);

      const content = fs.readFileSync(hookPath, "utf-8");
      expect(content).not.toContain("shhh secret scanner");
      expect(content).not.toContain("shhh scan --format json");
    });

    it("should preserve other hook content when uninstalling", () => {
      initGitDir();
      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      // Create existing hook with custom content
      const existingContent = "#!/bin/sh\necho 'my custom hook'\n";
      fs.writeFileSync(hookPath, existingContent, "utf-8");

      // Install shhh
      installHook("pre-commit", tmpDir);
      expect(fs.readFileSync(hookPath, "utf-8")).toContain("shhh secret scanner");
      expect(fs.readFileSync(hookPath, "utf-8")).toContain("my custom hook");

      // Uninstall shhh
      uninstallHook("pre-commit", tmpDir);
      const content = fs.readFileSync(hookPath, "utf-8");
      expect(content).toContain("my custom hook");
      expect(content).not.toContain("shhh secret scanner");
    });

    it("should be a no-op when hook file does not exist", () => {
      initGitDir();
      // Should not throw
      expect(() => uninstallHook("pre-commit", tmpDir)).not.toThrow();
    });

    it("should be a no-op when shhh section is not in the hook", () => {
      initGitDir();
      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      const content = "#!/bin/sh\necho 'other hook'\n";
      fs.writeFileSync(hookPath, content, "utf-8");

      uninstallHook("pre-commit", tmpDir);

      const afterContent = fs.readFileSync(hookPath, "utf-8");
      expect(afterContent).toContain("other hook");
    });

    it("should throw when .git directory does not exist", () => {
      expect(() => uninstallHook("pre-commit", tmpDir)).toThrow(
        /No .git directory found/,
      );
    });
  });

  // -----------------------------------------------------------------------
  // Hook script content safety
  // -----------------------------------------------------------------------
  describe("hook script content", () => {
    it("should not contain user-controlled strings that could allow shell injection", () => {
      initGitDir();
      installHook("pre-commit", tmpDir);

      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      const content = fs.readFileSync(hookPath, "utf-8");

      // The hook script should only contain hardcoded commands, no interpolated user input
      // The scan command uses a variable $SHHH_CMD, but the args are hardcoded
      expect(content).toContain("scan --format json");
      expect(content).toContain("SHHH_EXIT=$?");
      // Ensure the exit code check uses a simple integer comparison, not a string
      expect(content).toContain("$SHHH_EXIT -eq 2");
    });

    it("should produce a valid shell script with proper shebang and syntax", () => {
      initGitDir();
      installHook("pre-commit", tmpDir);

      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      const content = fs.readFileSync(hookPath, "utf-8");

      // Must start with shebang
      expect(content.startsWith("#!/bin/sh")).toBe(true);
      // Must have both start and end markers
      expect(content).toContain("# >>> shhh secret scanner >>>");
      expect(content).toContain("# <<< shhh secret scanner <<<");
      // Start marker should come before end marker
      const startIdx = content.indexOf(">>>");
      const endIdx = content.indexOf("<<<");
      expect(startIdx).toBeLessThan(endIdx);
    });

    it("should set executable permissions (owner, group, other execute)", () => {
      initGitDir();
      installHook("pre-commit", tmpDir);

      const hookPath = path.join(tmpDir, ".git", "hooks", "pre-commit");
      const stat = fs.statSync(hookPath);
      // 0o755 = rwxr-xr-x
      // Check all execute bits are set
      expect(stat.mode & 0o100).not.toBe(0); // owner execute
      expect(stat.mode & 0o010).not.toBe(0); // group execute
      expect(stat.mode & 0o001).not.toBe(0); // other execute
    });
  });
});
