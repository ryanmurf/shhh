/**
 * Shannon entropy calculator.
 *
 * Entropy measures the randomness/information density of a string.
 * High-entropy strings (> 4.5 bits per character) are likely to be
 * secrets such as API keys, tokens, or passwords.
 */

/**
 * Calculate the Shannon entropy of a string.
 *
 * @param str - The input string to measure
 * @returns Entropy value in bits per character. Range is 0 to log2(uniqueChars).
 *          A perfectly random hex string of length 32 scores around 3.5-4.0.
 *          Base64-encoded secrets typically score 4.5-6.0.
 */
export function calculateEntropy(str: string): number {
  if (str.length === 0) {
    return 0;
  }

  const freq = new Map<string, number>();

  for (const char of str) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  const len = str.length;
  let entropy = 0;

  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}
