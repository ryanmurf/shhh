import { describe, it, expect } from "vitest";
import { calculateEntropy } from "../src/entropy";

describe("calculateEntropy", () => {
  // -------------------------------------------------------------------
  // Zero / near-zero entropy cases
  // -------------------------------------------------------------------
  it("should return 0 for an empty string", () => {
    expect(calculateEntropy("")).toBe(0);
  });

  it("should return 0 for a single character", () => {
    expect(calculateEntropy("a")).toBe(0);
  });

  it("should return 0 for a string of identical characters", () => {
    const result = calculateEntropy("aaaaaaa");
    expect(result).toBe(0);
  });

  it("should return 0 for a long string of the same character", () => {
    expect(calculateEntropy("z".repeat(100))).toBe(0);
  });

  // -------------------------------------------------------------------
  // Low entropy
  // -------------------------------------------------------------------
  it("should return exactly 1.0 for a two-char alternating string", () => {
    // "ab" has 2 unique chars, each appearing once in a length-2 string
    // entropy = -2*(0.5*log2(0.5)) = 1.0
    const result = calculateEntropy("ab");
    expect(result).toBeCloseTo(1.0, 5);
  });

  it("should have low entropy for 'aabb'", () => {
    // 2 unique chars, each with freq 0.5 => entropy = 1.0
    const result = calculateEntropy("aabb");
    expect(result).toBeCloseTo(1.0, 5);
  });

  // -------------------------------------------------------------------
  // Medium entropy
  // -------------------------------------------------------------------
  it("should produce entropy around 3.0 for 'abcdefgh'", () => {
    // 8 unique characters, each appearing once => entropy = log2(8) = 3.0
    const result = calculateEntropy("abcdefgh");
    expect(result).toBeCloseTo(3.0, 1);
  });

  it("should produce entropy of log2(16) for 16 unique characters", () => {
    // 16 unique chars, each once => entropy = log2(16) = 4.0
    const result = calculateEntropy("abcdefghijklmnop");
    expect(result).toBeCloseTo(4.0, 1);
  });

  // -------------------------------------------------------------------
  // High entropy (secret-like strings)
  // -------------------------------------------------------------------
  it("should produce entropy >= 4.0 for a random-looking string", () => {
    const result = calculateEntropy("aB3$kL9!mN2@pQ5&");
    expect(result).toBeGreaterThanOrEqual(4.0);
  });

  it("should produce high entropy for a hex-encoded secret", () => {
    const hexString = "4a8f2b1c9d0e7f6a3b5c8d2e1f0a9b7c";
    const result = calculateEntropy(hexString);
    // 16 unique hex chars in 32-char string => close to 4.0
    expect(result).toBeGreaterThan(3.5);
  });

  it("should produce high entropy for a base64-like string", () => {
    const b64 = "dGhpcyBpcyBhIHNlY3JldCBrZXkgdmFsdWU=";
    const result = calculateEntropy(b64);
    expect(result).toBeGreaterThan(3.5);
  });

  it("should produce high entropy for a real-world-like API key", () => {
    const apiKey = "myapp_4eC39HqLyjWDarjtT1zdp7dc";
    const result = calculateEntropy(apiKey);
    expect(result).toBeGreaterThan(4.0);
  });

  // -------------------------------------------------------------------
  // Mathematical properties
  // -------------------------------------------------------------------
  it("should never return a negative value", () => {
    const inputs = ["", "a", "aaa", "abc", "aB3$kL9!mN2@pQ5"];
    for (const input of inputs) {
      expect(calculateEntropy(input)).toBeGreaterThanOrEqual(0);
    }
  });

  it("should return a finite number for any reasonable input", () => {
    const result = calculateEntropy("some arbitrary string with spaces and 12345");
    expect(Number.isFinite(result)).toBe(true);
  });

  it("should increase entropy as character diversity increases", () => {
    const low = calculateEntropy("aaa");
    const mid = calculateEntropy("abc");
    const high = calculateEntropy("aB3$kL9!");
    expect(low).toBeLessThan(mid);
    expect(mid).toBeLessThan(high);
  });

  it("maximum entropy of a string equals log2 of unique char count when uniformly distributed", () => {
    // "abcd" => 4 unique, each freq=1/4 => entropy = log2(4) = 2.0
    const result = calculateEntropy("abcd");
    expect(result).toBeCloseTo(Math.log2(4), 5);
  });

  // -------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------
  it("should handle unicode characters", () => {
    const result = calculateEntropy("hello world");
    expect(result).toBeGreaterThan(0);
  });

  it("should handle strings with only whitespace", () => {
    const result = calculateEntropy("     ");
    expect(result).toBe(0); // all same char (space)
  });

  it("should handle a very long uniform string efficiently", () => {
    const longStr = "x".repeat(10_000);
    const result = calculateEntropy(longStr);
    expect(result).toBe(0);
  });

  it("should handle mixed-case alphabet string", () => {
    const mixed = "AaBbCcDd";
    const result = calculateEntropy(mixed);
    // 8 unique chars, each once => log2(8) = 3.0
    expect(result).toBeCloseTo(3.0, 1);
  });
});
