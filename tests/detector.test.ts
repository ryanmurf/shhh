import { describe, it, expect } from "vitest";
import { detectSecrets } from "../src/detector";
import type { Finding } from "../src/types";

/**
 * Helper: run detectSecrets on a single line of content and return findings.
 * We assume detectSecrets accepts the file content (string) and returns Finding[].
 * The function signature we code against:
 *   detectSecrets(content: string, filePath?: string, platform?: string): Finding[]
 */
function detect(content: string): Finding[] {
  return detectSecrets(content, "/tmp/test-session.json", "claude");
}

// ---------------------------------------------------------------------------
// AWS Access Key IDs
// ---------------------------------------------------------------------------
describe("AWS Access Key ID detection", () => {
  it("should detect a valid AKIA-prefixed key", () => {
    const findings = detect("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const f = findings.find((f) => f.secretType.toLowerCase().includes("aws"));
    expect(f).toBeDefined();
  });

  it("should detect AKIA key embedded in JSON", () => {
    const json = '{"accessKeyId": "AKIAI44QH8DHBEXAMPLE"}';
    const findings = detect(json);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should mark AWS keys as critical severity", () => {
    const findings = detect("AKIAIOSFODNN7EXAMPLE");
    const awsFinding = findings.find((f) =>
      f.secretType.toLowerCase().includes("aws")
    );
    expect(awsFinding).toBeDefined();
    expect(awsFinding!.severity).toBe("critical");
  });

  it("should NOT match a partial AKIA prefix that is too short", () => {
    const findings = detect("AKIA12345"); // only 5 chars after AKIA, need 16
    const awsKey = findings.find(
      (f) =>
        f.secretType.toLowerCase().includes("aws") &&
        f.secretType.toLowerCase().includes("access")
    );
    expect(awsKey).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// AWS Secret Access Keys
// ---------------------------------------------------------------------------
describe("AWS Secret Access Key detection", () => {
  it("should detect a 40-character secret key after a known prefix", () => {
    const content =
      "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const findings = detect(content);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should detect secret key in export statement", () => {
    const content =
      'export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"';
    const findings = detect(content);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// GitHub Tokens
// ---------------------------------------------------------------------------
describe("GitHub token detection", () => {
  it("should detect ghp_ (personal access token)", () => {
    const findings = detect(
      "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const gh = findings.find((f) =>
      f.secretType.toLowerCase().includes("github")
    );
    expect(gh).toBeDefined();
  });

  it("should detect gho_ (OAuth access token)", () => {
    const findings = detect(
      "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should detect ghs_ (server-to-server token)", () => {
    const findings = detect(
      "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should detect ghr_ (refresh token)", () => {
    const findings = detect(
      "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should detect github_pat_ fine-grained tokens", () => {
    const findings = detect(
      "github_pat_11ABCDEF0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should mark GitHub tokens as high severity", () => {
    const findings = detect(
      "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    );
    const gh = findings.find((f) =>
      f.secretType.toLowerCase().includes("github")
    );
    expect(gh).toBeDefined();
    expect(gh!.severity).toBe("high");
  });
});

// ---------------------------------------------------------------------------
// Slack Tokens
// ---------------------------------------------------------------------------
describe("Slack token detection", () => {
  it("should detect xoxb- bot tokens", () => {
    const findings = detect(
      "SLACK_BOT_TOKEN=" + "xoxb" + "-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const slack = findings.find((f) =>
      f.secretType.toLowerCase().includes("slack")
    );
    expect(slack).toBeDefined();
  });

  it("should detect xoxp- user tokens", () => {
    const findings = detect("xoxp" + "-123456789012-123456789012-123456789012-abcdef1234567890abcdef1234567890ab");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should detect xoxs- session tokens", () => {
    const findings = detect("xoxs" + "-123456789012-123456789012-abcdef1234");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should mark Slack tokens as high severity", () => {
    const findings = detect(
      "xoxb" + "-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
    );
    const slack = findings.find((f) =>
      f.secretType.toLowerCase().includes("slack")
    );
    expect(slack).toBeDefined();
    expect(slack!.severity).toBe("high");
  });
});

// ---------------------------------------------------------------------------
// Generic API Key Patterns
// ---------------------------------------------------------------------------
describe("Generic API key pattern detection", () => {
  it("should detect api_key=<value> pattern", () => {
    const findings = detect(
      'api_key=myapp_4eC39HqLyjWDarjtT1zdp7dc'
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should detect apikey=<value> pattern (no underscore)", () => {
    const findings = detect(
      'apikey=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should detect API-KEY: header style", () => {
    const findings = detect(
      'API-KEY: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should mark generic API keys as medium severity", () => {
    const findings = detect(
      'api_key=myapp_4eC39HqLyjWDarjtT1zdp7dc'
    );
    const generic = findings.find(
      (f) =>
        f.severity === "medium" ||
        f.secretType.toLowerCase().includes("api")
    );
    expect(generic).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Private Keys
// ---------------------------------------------------------------------------
describe("Private key detection", () => {
  it("should detect RSA private key headers", () => {
    const content = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
-----END RSA PRIVATE KEY-----`;
    const findings = detect(content);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const pk = findings.find((f) =>
      f.secretType.toLowerCase().includes("private key")
    );
    expect(pk).toBeDefined();
  });

  it("should detect EC private key headers", () => {
    const content = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5GkNxNlIjGVLoAoGCCqGSM49
-----END EC PRIVATE KEY-----`;
    const findings = detect(content);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should detect generic PRIVATE KEY header", () => {
    const content = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZ
-----END PRIVATE KEY-----`;
    const findings = detect(content);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  // BUG-019: PEM header strings in code that processes PEM data should not match
  it("should NOT detect bare PEM header strings without key body", () => {
    const content = `String stripped = pem.replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")`;
    const findings = detect(content);
    const pk = findings.find((f) =>
      f.secretType.toLowerCase().includes("private key")
    );
    expect(pk).toBeUndefined();
  });

  it("should NOT detect PEM header in a condition check", () => {
    const content = `if (line.startsWith("-----BEGIN PRIVATE KEY-----")) { parsePem(line); }`;
    const findings = detect(content);
    const pk = findings.find((f) =>
      f.secretType.toLowerCase().includes("private key")
    );
    expect(pk).toBeUndefined();
  });

  it("should mark private keys as critical severity", () => {
    const content = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7Mhg
-----END RSA PRIVATE KEY-----`;
    const findings = detect(content);
    const pk = findings.find((f) =>
      f.secretType.toLowerCase().includes("private key")
    );
    expect(pk).toBeDefined();
    expect(pk!.severity).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// Database Connection Strings
// ---------------------------------------------------------------------------
describe("Database connection string detection", () => {
  it("should detect postgres:// connection strings with credentials", () => {
    const findings = detect(
      "DATABASE_URL=postgres://admin:s3cretP4ss@db.example.com:5432/mydb"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const db = findings.find(
      (f) =>
        f.secretType.toLowerCase().includes("database") ||
        f.secretType.toLowerCase().includes("connection")
    );
    expect(db).toBeDefined();
  });

  it("should detect mongodb+srv:// connection strings", () => {
    const findings = detect(
      "MONGO_URI=mongodb+srv://admin:p4ssw0rd@cluster0.abc123.mongodb.net/mydb"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should detect mysql:// connection strings", () => {
    const findings = detect(
      "mysql://root:password123@localhost:3306/appdb"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should not detect connection strings without credentials", () => {
    // A connection string with no user:pass should not be flagged
    const findings = detect("postgres://localhost:5432/mydb");
    const db = findings.find(
      (f) =>
        f.secretType.toLowerCase().includes("database") ||
        f.secretType.toLowerCase().includes("connection")
    );
    expect(db).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// JWT Detection
// ---------------------------------------------------------------------------
describe("JWT detection", () => {
  // A real-looking JWT (header.payload.signature, each base64url-encoded)
  const sampleJwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

  it("should detect a standard JWT", () => {
    const findings = detect(`Authorization: Bearer ${sampleJwt}`);
    // Should detect at least the JWT (might also detect the Bearer pattern)
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const jwt = findings.find((f) =>
      f.secretType.toLowerCase().includes("jwt")
    );
    expect(jwt).toBeDefined();
  });

  it("should detect JWT assigned to a variable", () => {
    const findings = detect(`const token = "${sampleJwt}";`);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("should not flag a string that merely starts with eyJ but has no dots", () => {
    const findings = detect("eyJhbGciOiJIUzI1NiJ9");
    const jwt = findings.find((f) =>
      f.secretType.toLowerCase().includes("jwt")
    );
    expect(jwt).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Bearer Tokens
// ---------------------------------------------------------------------------
describe("Bearer token detection", () => {
  it("should detect Bearer followed by a long token string", () => {
    const findings = detect(
      "Authorization: Bearer sl.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const bearer = findings.find(
      (f) =>
        f.secretType.toLowerCase().includes("bearer") ||
        f.secretType.toLowerCase().includes("token")
    );
    expect(bearer).toBeDefined();
  });

  it("should not flag 'Bearer' keyword alone without a token value", () => {
    const findings = detect("Authorization: Bearer ");
    const bearer = findings.find((f) =>
      f.secretType.toLowerCase().includes("bearer")
    );
    expect(bearer).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// False Positive Resistance
// ---------------------------------------------------------------------------
describe("False positive resistance", () => {
  it("should NOT flag placeholder value 'your-api-key-here'", () => {
    const findings = detect("api_key=your-api-key-here");
    expect(findings.length).toBe(0);
  });

  it("should NOT flag placeholder value 'xxxxxxxxxxxx'", () => {
    const findings = detect("api_key=xxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    expect(findings.length).toBe(0);
  });

  it("should NOT flag 'TODO' or 'REPLACE_ME' placeholders", () => {
    const findings = detect("api_key=TODO");
    expect(findings.length).toBe(0);
  });

  it("should NOT flag example keys from documentation", () => {
    // The classic AWS example key
    const findings = detect("api_key=EXAMPLE1234567890");
    // Even if it pattern-matches, a good detector filters these out
    // At minimum it should not be high/critical severity
    const critical = findings.filter(
      (f) => f.severity === "critical" || f.severity === "high"
    );
    expect(critical.length).toBe(0);
  });

  it("should NOT flag empty string values", () => {
    const findings = detect('api_key=""');
    expect(findings.length).toBe(0);
  });

  it("should NOT flag the word 'password' in isolation", () => {
    const findings = detect("Enter your password:");
    expect(findings.length).toBe(0);
  });

  it("should NOT flag low-entropy repeated strings", () => {
    const findings = detect("api_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    expect(findings.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------
describe("Redaction of matched secrets", () => {
  it("should redact matched value showing only first 4 and last 4 chars", () => {
    const findings = detect("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
    const gh = findings.find((f) =>
      f.secretType.toLowerCase().includes("github")
    );
    expect(gh).toBeDefined();
    // The match field should be redacted: first 4 ... last 4
    // e.g., "ghp_...ghij" or "ghp_****ghij"
    const match = gh!.match;
    expect(match).toContain("ghp_");
    expect(match).toContain("ghij");
    // The full original value should NOT appear in the match field
    expect(match).not.toBe("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
    expect(match.length).toBeLessThan(
      "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij".length
    );
  });

  it("should redact AWS keys in the same manner", () => {
    const findings = detect("AKIAIOSFODNN7EXAMPLE");
    const aws = findings.find((f) =>
      f.secretType.toLowerCase().includes("aws")
    );
    expect(aws).toBeDefined();
    expect(aws!.match).toContain("AKIA");
    expect(aws!.match).not.toBe("AKIAIOSFODNN7EXAMPLE");
  });
});

// ---------------------------------------------------------------------------
// Finding shape
// ---------------------------------------------------------------------------
describe("Finding object shape", () => {
  it("should return findings with all required fields", () => {
    const findings = detect(
      "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const f = findings[0];
    expect(f).toHaveProperty("id");
    expect(f).toHaveProperty("secretType");
    expect(f).toHaveProperty("severity");
    expect(f).toHaveProperty("match");
    expect(f).toHaveProperty("filePath");
    expect(f).toHaveProperty("line");
    expect(f).toHaveProperty("column");
    expect(f).toHaveProperty("platform");
    expect(f).toHaveProperty("context");
  });

  it("should populate filePath from the argument", () => {
    const findings = detectSecrets(
      "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
      "/home/user/.claude/session.json",
      "claude"
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].filePath).toBe("/home/user/.claude/session.json");
  });

  it("should return an empty array for benign content", () => {
    const findings = detect("Hello world, this is just a normal sentence.");
    expect(findings).toEqual([]);
  });
});
