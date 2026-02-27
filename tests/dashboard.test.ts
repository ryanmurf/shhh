import { describe, it, expect } from "vitest";
import { renderDashboard } from "../src/dashboard";
import type { Finding, ScanResult } from "../src/types";

/**
 * Helper to build a realistic Finding object for tests.
 */
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "test-001",
    secretType: "GitHub Token",
    severity: "high",
    match: "ghp_****ghij",
    filePath: "/home/user/.claude/session.json",
    line: 42,
    column: 15,
    platform: "claude",
    context: '..."token": "ghp_****ghij"...',
    ...overrides,
  };
}

/**
 * Helper to build a ScanResult for tests.
 */
function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    findings: [makeFinding()],
    filesScanned: 5,
    platformsScanned: ["claude"],
    scanDurationMs: 120,
    ...overrides,
  };
}

/**
 * Strip ANSI escape codes from a string so assertions work on plain text.
 */
function stripAnsi(str: string): string {
  return str.replace(/\x1b\[[0-9;]*m/g, "");
}

// ---------------------------------------------------------------------------
// renderDashboard
// ---------------------------------------------------------------------------
describe("renderDashboard", () => {
  it("should return a string (not undefined)", () => {
    const result = renderDashboard(makeScanResult());
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });

  it("should contain box-drawing characters", () => {
    const result = renderDashboard(makeScanResult());
    // Check for the unicode box-drawing characters used in borders
    expect(result).toContain("\u2554"); // top-left corner
    expect(result).toContain("\u2557"); // top-right corner
    expect(result).toContain("\u255A"); // bottom-left corner
    expect(result).toContain("\u255D"); // bottom-right corner
    expect(result).toContain("\u2551"); // vertical bar
    expect(result).toContain("\u2550"); // horizontal bar
    expect(result).toContain("\u2560"); // left T-junction
    expect(result).toContain("\u2563"); // right T-junction
  });

  it("should contain severity counts", () => {
    const findings = [
      makeFinding({ id: "f-1", severity: "critical" }),
      makeFinding({ id: "f-2", severity: "critical" }),
      makeFinding({ id: "f-3", severity: "high" }),
      makeFinding({ id: "f-4", severity: "medium" }),
      makeFinding({ id: "f-5", severity: "low" }),
    ];
    const result = stripAnsi(renderDashboard(makeScanResult({ findings })));

    // The severity labels and their counts should appear
    expect(result).toContain("Critical");
    expect(result).toContain("High");
    expect(result).toContain("Medium");
    expect(result).toContain("Low");
    // Critical count should be 2
    expect(result).toContain("2");
    // High, Medium, Low each 1
    expect(result).toContain("1");
  });

  it("should contain platform names", () => {
    const findings = [
      makeFinding({ id: "f-1", platform: "claude" }),
      makeFinding({ id: "f-2", platform: "codex" }),
      makeFinding({ id: "f-3", platform: "copilot" }),
    ];
    const result = stripAnsi(
      renderDashboard(
        makeScanResult({
          findings,
          platformsScanned: ["claude", "codex", "copilot"],
        }),
      ),
    );
    expect(result).toContain("claude");
    expect(result).toContain("codex");
    expect(result).toContain("copilot");
  });

  it("should handle empty findings", () => {
    const result = stripAnsi(
      renderDashboard(
        makeScanResult({
          findings: [],
          platformsScanned: ["claude"],
        }),
      ),
    );
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
    // Should indicate no secrets
    expect(result).toContain("No secrets found");
    // Should still contain box drawing
    expect(result).toContain("\u2554");
    expect(result).toContain("\u255D");
  });

  it("should handle a single finding", () => {
    const result = stripAnsi(
      renderDashboard(
        makeScanResult({
          findings: [makeFinding({ severity: "critical", secretType: "AWS Key" })],
        }),
      ),
    );
    expect(result).toContain("Critical");
    expect(result).toContain("1");
    expect(result).toContain("AWS Key");
  });

  it("should sort top types by count descending", () => {
    const findings = [
      makeFinding({ id: "f-1", secretType: "JWT" }),
      makeFinding({ id: "f-2", secretType: "JWT" }),
      makeFinding({ id: "f-3", secretType: "JWT" }),
      makeFinding({ id: "f-4", secretType: "GitHub PAT" }),
      makeFinding({ id: "f-5", secretType: "GitHub PAT" }),
      makeFinding({ id: "f-6", secretType: "Bearer Token" }),
    ];
    const result = stripAnsi(renderDashboard(makeScanResult({ findings })));

    // JWT (3) should appear before GitHub PAT (2) which should appear before Bearer Token (1)
    const jwtIndex = result.indexOf("JWT");
    const ghIndex = result.indexOf("GitHub PAT");
    const bearerIndex = result.indexOf("Bearer Token");

    expect(jwtIndex).toBeLessThan(ghIndex);
    expect(ghIndex).toBeLessThan(bearerIndex);
  });

  it("should produce proportional bar widths", () => {
    // Create findings where critical has 1 and high has 4 findings
    // The high bar should be longer than the critical bar
    const findings = [
      makeFinding({ id: "f-1", severity: "critical" }),
      makeFinding({ id: "f-2", severity: "high" }),
      makeFinding({ id: "f-3", severity: "high" }),
      makeFinding({ id: "f-4", severity: "high" }),
      makeFinding({ id: "f-5", severity: "high" }),
    ];
    const result = stripAnsi(renderDashboard(makeScanResult({ findings })));

    // Find the lines containing severity bars
    const lines = result.split("\n");
    const criticalLine = lines.find((l) => l.includes("Critical"));
    const highLine = lines.find((l) => l.includes("High"));

    expect(criticalLine).toBeDefined();
    expect(highLine).toBeDefined();

    // Count block characters in each line
    const blockCharsRegex = /[\u2588\u2589\u258A\u258B\u258C\u258D\u258E\u258F]/g;
    const criticalBlocks = (criticalLine!.match(blockCharsRegex) || []).length;
    const highBlocks = (highLine!.match(blockCharsRegex) || []).length;

    // High (4 findings) should have more block chars than Critical (1 finding)
    expect(highBlocks).toBeGreaterThan(criticalBlocks);
  });

  it("should include the dashboard title", () => {
    const result = stripAnsi(renderDashboard(makeScanResult()));
    expect(result).toContain("shhh");
    expect(result).toContain("Scan Dashboard");
  });

  it("should display files scanned count", () => {
    const result = stripAnsi(
      renderDashboard(makeScanResult({ filesScanned: 2690 })),
    );
    expect(result).toContain("2,690");
  });

  it("should display scan duration in seconds", () => {
    const result = stripAnsi(
      renderDashboard(makeScanResult({ scanDurationMs: 16700 })),
    );
    expect(result).toContain("16.7s");
  });

  it("should limit top secret types to at most 5", () => {
    // Create 7 distinct secret types
    const types = [
      "TypeA", "TypeB", "TypeC", "TypeD", "TypeE", "TypeF", "TypeG",
    ];
    const findings = types.map((t, i) =>
      makeFinding({ id: `f-${i}`, secretType: t }),
    );
    const result = stripAnsi(renderDashboard(makeScanResult({ findings })));

    // Only 5 should have rank numbers
    expect(result).toContain("1.");
    expect(result).toContain("5.");
    // 6th and 7th should not be present as ranked items
    // (they might appear in other sections, so just check the ranking section)
    const topTypesSection = result.split("TOP SECRET TYPES")[1]?.split("PLATFORM BREAKDOWN")[0];
    expect(topTypesSection).toBeDefined();
    expect(topTypesSection).not.toContain("6.");
  });

  // Dashboard edge cases
  it("should handle all severity counts being zero without division by zero", () => {
    // Empty findings but with a scanned platform (0 findings, bars should be empty)
    const result = renderDashboard(
      makeScanResult({
        findings: [],
        platformsScanned: ["claude"],
        filesScanned: 0,
      }),
    );
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
    // Should not throw or produce NaN
    expect(result).not.toContain("NaN");
    expect(result).not.toContain("undefined");
  });

  it("should handle zero filesScanned and zero duration", () => {
    const result = stripAnsi(
      renderDashboard(
        makeScanResult({
          findings: [],
          platformsScanned: [],
          filesScanned: 0,
          scanDurationMs: 0,
        }),
      ),
    );
    expect(result).toContain("0");
    expect(result).toContain("0.0s");
    expect(result).not.toContain("NaN");
  });

  it("should handle very large file counts with thousands separator", () => {
    const result = stripAnsi(
      renderDashboard(
        makeScanResult({
          filesScanned: 1234567,
        }),
      ),
    );
    expect(result).toContain("1,234,567");
  });

  it("should handle a single platform with zero findings in platform breakdown", () => {
    const result = stripAnsi(
      renderDashboard(
        makeScanResult({
          findings: [],
          platformsScanned: ["claude", "codex"],
        }),
      ),
    );
    // Both platforms should appear in breakdown even with 0 findings
    expect(result).toContain("claude");
    expect(result).toContain("codex");
  });
});
