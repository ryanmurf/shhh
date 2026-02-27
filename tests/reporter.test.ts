import { describe, it, expect } from "vitest";
import { formatText, formatJson } from "../src/reporter";
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

// ---------------------------------------------------------------------------
// formatText
// ---------------------------------------------------------------------------
describe("formatText", () => {
  it("should return a string", () => {
    const result = formatText(makeScanResult());
    expect(typeof result).toBe("string");
  });

  it("should include the secret type in the output", () => {
    const result = formatText(makeScanResult());
    expect(result).toContain("GitHub Token");
  });

  it("should include the severity level in the output", () => {
    const result = formatText(makeScanResult());
    // Check case-insensitively since it might be uppercased
    expect(result.toLowerCase()).toContain("high");
  });

  it("should include the file path in the output", () => {
    const result = formatText(makeScanResult());
    expect(result).toContain("/home/user/.claude/session.json");
  });

  it("should include the line number in the output", () => {
    const result = formatText(makeScanResult());
    expect(result).toContain("42");
  });

  it("should handle empty findings array gracefully", () => {
    const result = formatText(makeScanResult({ findings: [] }));
    expect(typeof result).toBe("string");
    // Should not throw, and should produce some output (e.g., "No findings" or summary)
    expect(result.length).toBeGreaterThan(0);
  });

  it("should include the redacted match value", () => {
    const result = formatText(makeScanResult());
    expect(result).toContain("ghp_****ghij");
  });

  it("should handle multiple findings", () => {
    const findings = [
      makeFinding({ id: "f-1", secretType: "AWS Access Key", severity: "critical" }),
      makeFinding({ id: "f-2", secretType: "Slack Token", severity: "high" }),
      makeFinding({ id: "f-3", secretType: "Generic API Key", severity: "medium" }),
    ];
    const result = formatText(makeScanResult({ findings }));
    expect(result).toContain("AWS Access Key");
    expect(result).toContain("Slack Token");
    expect(result).toContain("Generic API Key");
  });

  it("should include platform information", () => {
    const result = formatText(makeScanResult());
    expect(result.toLowerCase()).toContain("claude");
  });

  it("should display different severity levels distinctly", () => {
    const critical = formatText(
      makeScanResult({
        findings: [makeFinding({ severity: "critical" })],
      })
    );
    const medium = formatText(
      makeScanResult({
        findings: [makeFinding({ severity: "medium" })],
      })
    );
    // Both should contain their respective severity strings
    expect(critical.toLowerCase()).toContain("critical");
    expect(medium.toLowerCase()).toContain("medium");
  });
});

// ---------------------------------------------------------------------------
// formatJson
// ---------------------------------------------------------------------------
describe("formatJson", () => {
  it("should return a string", () => {
    const result = formatJson(makeScanResult());
    expect(typeof result).toBe("string");
  });

  it("should return valid parseable JSON", () => {
    const result = formatJson(makeScanResult());
    expect(() => JSON.parse(result)).not.toThrow();
  });

  it("should contain findings array in the parsed output", () => {
    const result = formatJson(makeScanResult());
    const parsed = JSON.parse(result);
    // Findings might be at top level or nested; check both
    const findings = parsed.findings ?? parsed;
    expect(Array.isArray(findings)).toBe(true);
  });

  it("should include severity in JSON output", () => {
    const result = formatJson(makeScanResult());
    const parsed = JSON.parse(result);
    const jsonStr = JSON.stringify(parsed);
    expect(jsonStr).toContain("high");
  });

  it("should include secretType in JSON output", () => {
    const result = formatJson(makeScanResult());
    const parsed = JSON.parse(result);
    const jsonStr = JSON.stringify(parsed);
    expect(jsonStr).toContain("GitHub Token");
  });

  it("should handle empty findings array and produce valid JSON", () => {
    const result = formatJson(makeScanResult({ findings: [] }));
    expect(() => JSON.parse(result)).not.toThrow();
    const parsed = JSON.parse(result);
    const findings = parsed.findings ?? parsed;
    if (Array.isArray(findings)) {
      expect(findings.length).toBe(0);
    }
  });

  it("should include file path in JSON output", () => {
    const result = formatJson(makeScanResult());
    expect(result).toContain("/home/user/.claude/session.json");
  });

  it("should include scan metadata", () => {
    const result = formatJson(makeScanResult({ filesScanned: 10 }));
    const parsed = JSON.parse(result);
    // Should contain filesScanned somewhere in the output
    const jsonStr = JSON.stringify(parsed);
    expect(jsonStr).toContain("10");
  });

  it("should serialize multiple findings correctly", () => {
    const findings = [
      makeFinding({ id: "f-1", secretType: "AWS Access Key" }),
      makeFinding({ id: "f-2", secretType: "Private Key" }),
    ];
    const result = formatJson(makeScanResult({ findings }));
    const parsed = JSON.parse(result);
    const parsedFindings = parsed.findings ?? parsed;
    expect(Array.isArray(parsedFindings)).toBe(true);
    expect(parsedFindings.length).toBe(2);
  });

  it("should include platform in JSON output", () => {
    const result = formatJson(makeScanResult());
    const parsed = JSON.parse(result);
    const jsonStr = JSON.stringify(parsed);
    expect(jsonStr).toContain("claude");
  });
});

// ---------------------------------------------------------------------------
// Cross-format consistency
// ---------------------------------------------------------------------------
describe("Cross-format consistency", () => {
  it("both formats should handle a single critical finding", () => {
    const scanResult = makeScanResult({
      findings: [
        makeFinding({
          secretType: "RSA Private Key",
          severity: "critical",
          match: "-----****KEY-----",
        }),
      ],
    });
    const text = formatText(scanResult);
    const json = formatJson(scanResult);

    expect(text).toContain("RSA Private Key");
    expect(json).toContain("RSA Private Key");
    expect(text.toLowerCase()).toContain("critical");
    expect(json).toContain("critical");
  });

  it("both formats should handle zero findings without error", () => {
    const scanResult = makeScanResult({ findings: [] });
    expect(() => formatText(scanResult)).not.toThrow();
    expect(() => formatJson(scanResult)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// ScoredFinding display in formatText
// ---------------------------------------------------------------------------
describe("formatText with scored findings", () => {
  it("should display score, context type, and risk factors for ScoredFindings", () => {
    const scoredFinding = {
      ...makeFinding(),
      score: 85,
      contextType: "config" as const,
      riskFactors: ["Cloud credential", "Secret in config file"],
    };
    const result = formatText(makeScanResult({ findings: [scoredFinding] }));
    expect(result).toContain("85");
    expect(result).toContain("100");
    expect(result).toContain("config");
    expect(result).toContain("Cloud credential");
    expect(result).toContain("Secret in config file");
  });

  it("should handle ScoredFindings with empty risk factors", () => {
    const scoredFinding = {
      ...makeFinding(),
      score: 60,
      contextType: "unknown" as const,
      riskFactors: [],
    };
    const result = formatText(makeScanResult({ findings: [scoredFinding] }));
    expect(result).toContain("60");
    // Should not include Risk: line when empty
    // (the code only prints risk factors if length > 0)
  });
});
