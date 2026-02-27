import { describe, it, expect } from "vitest";
import { scoreFinding, scoreFindings } from "../src/scoring";
import type { Finding } from "../src/types";

/**
 * Helper to build a Finding for tests.
 */
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "test-001",
    secretType: "GitHub Personal Access Token",
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

// ---------------------------------------------------------------------------
// Base score from severity
// ---------------------------------------------------------------------------
describe("base score from severity", () => {
  it("should assign base score 80 for critical severity", () => {
    const finding = makeFinding({ severity: "critical", secretType: "RSA Private Key" });
    const scored = scoreFinding(finding, "some line content");
    // critical=80, no context modifiers for plain line
    expect(scored.score).toBeGreaterThanOrEqual(80);
  });

  it("should assign base score 60 for high severity", () => {
    const finding = makeFinding({ severity: "high", secretType: "Slack Bot Token" });
    const scored = scoreFinding(finding, "some line content");
    // high=60, no context match, but GitHub is not in secretType
    // Slack is not a cloud credential, no path adjustment
    expect(scored.score).toBe(60);
  });

  it("should assign base score 40 for medium severity", () => {
    const finding = makeFinding({ severity: "medium", secretType: "Generic API Key" });
    const scored = scoreFinding(finding, "some line content");
    expect(scored.score).toBe(40);
  });

  it("should assign base score 20 for low severity", () => {
    const finding = makeFinding({ severity: "low", secretType: "High-Entropy String" });
    const scored = scoreFinding(finding, "some line content");
    expect(scored.score).toBe(20);
  });
});

// ---------------------------------------------------------------------------
// Context type detection
// ---------------------------------------------------------------------------
describe("context type detection", () => {
  it("should detect user_input from role:user in line content", () => {
    const finding = makeFinding();
    const scored = scoreFinding(finding, '{"role":"user","content":"my secret ghp_AbC123"}');
    expect(scored.contextType).toBe("user_input");
    // high=60 + user_input=15 + cloud=5 = 80
    expect(scored.score).toBe(80);
  });

  it("should detect user_input with spaced JSON", () => {
    const finding = makeFinding();
    const scored = scoreFinding(finding, '{"role": "user", "content": "password123"}');
    expect(scored.contextType).toBe("user_input");
  });

  it("should detect ai_output from role:assistant", () => {
    const finding = makeFinding();
    const scored = scoreFinding(finding, '{"role":"assistant","content":"Here is your key: ghp_AbC123"}');
    expect(scored.contextType).toBe("ai_output");
    // high=60 + ai_output=5 + cloud=5 = 70
    expect(scored.score).toBe(70);
  });

  it("should detect tool_result from type:tool_result", () => {
    const finding = makeFinding();
    const scored = scoreFinding(finding, '{"type":"tool_result","content":"key=ghp_AbC123"}');
    expect(scored.contextType).toBe("tool_result");
  });

  it("should detect tool_result from tool_use", () => {
    const finding = makeFinding();
    const scored = scoreFinding(finding, '{"tool_use": {"name": "bash", "input": "ghp_AbC123"}}');
    expect(scored.contextType).toBe("tool_result");
  });

  it("should detect config context from file path containing config", () => {
    const finding = makeFinding({
      filePath: "/home/user/.config/shhh/settings.json",
    });
    const scored = scoreFinding(finding, "api_key=ghp_AbC123Def456");
    expect(scored.contextType).toBe("config");
    // high=60 + config=20 + cloud=5 = 85
    expect(scored.score).toBe(85);
  });

  it("should detect config context from .mcp path", () => {
    const finding = makeFinding({
      filePath: "/home/user/.mcp/servers.json",
    });
    const scored = scoreFinding(finding, "token: ghp_AbC123Def456");
    expect(scored.contextType).toBe("config");
  });

  it("should return unknown for unrecognized content/paths", () => {
    const finding = makeFinding({
      filePath: "/home/user/.claude/session.json",
    });
    const scored = scoreFinding(finding, "some random line with a secret");
    expect(scored.contextType).toBe("unknown");
  });

  // BUG-017: detectContextType missed "role": "assistant" with space after colon
  it("should detect ai_output with spaced JSON (role: assistant)", () => {
    const finding = makeFinding();
    const scored = scoreFinding(finding, '{"role": "assistant", "content": "Here is your key: ghp_AbC123"}');
    expect(scored.contextType).toBe("ai_output");
    // high=60 + ai_output=5 + cloud=5 = 70
    expect(scored.score).toBe(70);
  });

  // BUG-018: detectContextType missed "type": "tool_result" with space after colon
  it("should detect tool_result with spaced JSON (type: tool_result)", () => {
    const finding = makeFinding();
    const scored = scoreFinding(finding, '{"type": "tool_result", "content": "key=ghp_AbC123"}');
    expect(scored.contextType).toBe("tool_result");
  });

  // Edge case: line contains both "role":"user" and "role":"assistant"
  it("should prioritize user_input when line contains both user and assistant roles", () => {
    const finding = makeFinding();
    const scored = scoreFinding(finding, '{"role":"user","content":"echo role:assistant ghp_AbC123"}');
    // user_input should win because it is checked first
    expect(scored.contextType).toBe("user_input");
  });
});

// ---------------------------------------------------------------------------
// Risk factor adjustments
// ---------------------------------------------------------------------------
describe("risk factor adjustments", () => {
  it("should add cloud credential bonus for AWS secrets", () => {
    const finding = makeFinding({
      secretType: "AWS Access Key ID",
      severity: "critical",
    });
    const scored = scoreFinding(finding, "AKIAI44QH8DHBXYZ1234");
    expect(scored.riskFactors).toContain("Cloud credential");
    // critical=80 + cloud=5 = 85
    expect(scored.score).toBe(85);
  });

  it("should add cloud credential bonus for GitHub secrets", () => {
    const finding = makeFinding({
      secretType: "GitHub Personal Access Token",
      severity: "high",
    });
    const scored = scoreFinding(finding, "ghp_AbCdEfGhIjKlMnOpQrStUvWx");
    expect(scored.riskFactors).toContain("Cloud credential");
    // high=60 + cloud=5 = 65
    expect(scored.score).toBe(65);
  });

  it("should discount archived sessions", () => {
    const finding = makeFinding({
      filePath: "/home/user/.claude/archive/old-session.json",
      severity: "high",
    });
    const scored = scoreFinding(finding, "ghp_AbCdEfGhIjKlMnOpQrStUvWx");
    expect(scored.riskFactors).toContain("Archived session");
    // high=60 + cloud=5 - archive=10 = 55
    expect(scored.score).toBe(55);
  });

  it("should discount likely test data", () => {
    const finding = makeFinding({
      severity: "high",
      secretType: "Slack Bot Token",
    });
    const scored = scoreFinding(finding, "EXAMPLE_TOKEN=" + "xoxb" + "-123456789012-abc");
    expect(scored.riskFactors).toContain("Likely test data");
    // high=60 - test=20 = 40
    expect(scored.score).toBe(40);
  });

  it("should clamp score to minimum of 0", () => {
    const finding = makeFinding({
      severity: "low",
      filePath: "/home/user/.claude/archive/old.json",
      secretType: "High-Entropy String",
    });
    // low=20 - archive=10 - test=20 => would be -10, clamp to 0
    const scored = scoreFinding(finding, "test_key=EXAMPLE_xxxxxxxxxxxx");
    expect(scored.score).toBeGreaterThanOrEqual(0);
  });

  it("should clamp score to maximum of 100", () => {
    const finding = makeFinding({
      severity: "critical",
      secretType: "AWS Access Key ID",
      filePath: "/home/user/.config/plugin/aws.json",
    });
    // critical=80 + config=20 + cloud=5 = 105, clamp to 100
    const scored = scoreFinding(finding, '{"role":"user","content":"AKIAIOSFODNN7EXAMPLE"}');
    expect(scored.score).toBeLessThanOrEqual(100);
  });
});

// ---------------------------------------------------------------------------
// Batch scoring with deduplication
// ---------------------------------------------------------------------------
describe("scoreFindings (batch)", () => {
  it("should score all findings in the array", () => {
    const findings = [
      makeFinding({ id: "f1", match: "ghp_****aaaa" }),
      makeFinding({ id: "f2", match: "ghp_****bbbb", severity: "critical", secretType: "AWS Access Key" }),
    ];

    const getLine = () => "some content line";
    const scored = scoreFindings(findings, getLine);

    expect(scored).toHaveLength(2);
    expect(scored[0].score).toBeGreaterThan(0);
    expect(scored[1].score).toBeGreaterThan(0);
    expect(scored[0]).toHaveProperty("contextType");
    expect(scored[0]).toHaveProperty("riskFactors");
  });

  it("should add repetition bonus for duplicate matches", () => {
    const findings = [
      makeFinding({ id: "f1", match: "ghp_****same", line: 10 }),
      makeFinding({ id: "f2", match: "ghp_****same", line: 20 }),
      makeFinding({ id: "f3", match: "ghp_****same", line: 30 }),
    ];

    const getLine = () => "normal content";
    const scored = scoreFindings(findings, getLine);

    // All three should have the repetition factor
    for (const s of scored) {
      expect(s.riskFactors).toContain("Secret repeated 3 times");
    }

    // Score should include +10 (2 extra occurrences * 5)
    // high=60 + cloud=5 + repetition=10 = 75
    expect(scored[0].score).toBe(75);
  });

  it("should cap repetition bonus at +15", () => {
    const findings = Array.from({ length: 6 }, (_, i) =>
      makeFinding({ id: `f${i}`, match: "ghp_****same", line: i + 1 }),
    );

    const getLine = () => "normal content";
    const scored = scoreFindings(findings, getLine);

    // 5 extra occurrences * 5 = 25, but capped at 15
    // high=60 + cloud=5 + repetition=15 = 80
    expect(scored[0].score).toBe(80);
    expect(scored[0].riskFactors).toContain("Secret repeated 6 times");
  });

  it("should pass correct line content to each finding", () => {
    const findings = [
      makeFinding({ id: "f1", line: 1, filePath: "/tmp/a.json" }),
      makeFinding({ id: "f2", line: 2, filePath: "/tmp/a.json" }),
    ];

    const lines = ['{"role":"user","content":"secret"}', "normal line"];
    const getLine = (_filePath: string, line: number) => lines[line - 1] ?? "";
    const scored = scoreFindings(findings, getLine);

    expect(scored[0].contextType).toBe("user_input");
    expect(scored[1].contextType).toBe("unknown");
  });

  it("should return empty array for empty findings", () => {
    const scored = scoreFindings([], () => "");
    expect(scored).toEqual([]);
  });
});
