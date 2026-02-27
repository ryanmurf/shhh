# shhh - Roadmap

> CLI tool that scans AI coding assistant sessions for leaked secrets.

## Supported Platforms

- **Claude Code** (`~/.claude/` and variants like `~/.claude-hd`, `~/.claude-max`)
- **OpenAI Codex CLI** (`~/.codex/` and variants)
- **GitHub Copilot CLI** (`~/.copilot/`, `~/.config/github-copilot/`, and variants)

---

## Phase 1 - Core Engine (MVP)

- [x] Project scaffolding (package.json, tsconfig, eslint)
- [x] Session file discovery — locate and enumerate session files across all three platforms
- [x] Secret detection engine — regex-based pattern matching for common secret types:
  - AWS keys, GitHub tokens, Slack tokens, generic API keys
  - Private keys (RSA, EC, PGP)
  - Database connection strings
  - JWTs, Bearer tokens
  - High-entropy string detection (Shannon entropy)
- [x] CLI interface (`shhh scan`, `shhh scan --platform claude`, etc.)
- [x] Human-readable terminal report with severity levels
- [x] Unit tests for detection engine

## Phase 2 - Hardening

- [x] JSON / SARIF output format for CI integration
- [x] `.shhhignore` file support (allowlist known-safe patterns)
- [x] Incremental scanning (`--incremental` flag, tracks last-scanned position)
- [x] Custom rule definitions (`~/.config/shhh/rules.json`)
- [x] False-positive reduction heuristics (placeholder detection, example key filtering)
- [x] High-entropy string noise reduction (5-layer context-aware filtering — 99.8% noise reduction)
- [x] Line-by-line streaming + 8x parallel concurrency (141s -> 16.7s)
- [x] Variant directory auto-discovery (e.g., `~/.claude-hd`, `~/.claude-max`)

## Phase 3 - Advanced Features

- [x] `shhh watch` — real-time monitoring mode (tail sessions as they grow)
- [x] `shhh redact` — redaction of found secrets (`--dry-run`, `--no-backup`)
- [x] Git hook integration (`shhh hook install/uninstall --type pre-commit|pre-push`)
- [x] Severity scoring model (`--scored` flag, context-aware: user input vs AI output vs tool result vs config)
- [x] Dashboard TUI (`--format dashboard`, unicode box-drawing, bar charts, color-coded)

---

## Known Bugs & Issues

> _Populated by QA during development._

| ID | Severity | Description | Phase | Status |
|----|----------|-------------|-------|--------|
| BUG-001 | High | GitHub token patterns incorrectly classified as "critical" severity instead of "high" in detector.ts | Phase 1 | Fixed |
| BUG-002 | High | Slack xoxp- user token regex missing required fourth numeric segment; pattern expected 3 dash-separated parts but real tokens have 4 | Phase 1 | Fixed |
| BUG-003 | High | Slack xoxs- session token regex minimum length too strict (40+); tokens with 20+ chars after prefix were not detected | Phase 1 | Fixed |
| BUG-004 | Medium | JWT findings not identifiable by type; secretType was "JSON Web Token" which does not contain the substring "jwt" for programmatic lookup | Phase 1 | Fixed |
| BUG-005 | High | No false-positive filtering for placeholder values (e.g., "your-api-key-here", "xxxxxxxxxxxx", repeated single-character strings) in the Generic API Key pattern | Phase 2 | Fixed |
| BUG-006 | High | discoverSessionFiles was async (returned Promise) but consumers expected synchronous return; also accepted a bare Platform string instead of an options object { platform } | Phase 1 | Fixed |
| BUG-007 | Low | Claude platform config only matched .jsonl files; .json session files were not discovered | Phase 1 | Fixed |
| BUG-008 | Low | Entropy test used strict > 4.0 comparison for a 16-unique-char string whose entropy is exactly log2(16) = 4.0; boundary condition fixed to >= 4.0 in test | Phase 1 | Fixed |
| BUG-009 | Critical | High-entropy string detector produces ~38,700 false positives on real session data; base64-encoded file content, tool results, and conversation data in JSONL sessions are flagged as secrets. Fixed with 5-layer filtering: raised threshold to 5.0, 100-char max length, context keyword skip, per-file cap of 10, conversation line skip. Result: 38,723 -> 81 entropy findings. | Phase 2 | Fixed |
| BUG-010 | High | Scanner loaded entire files into memory and ran global regex; 700MB of session data caused 100% CPU hang. Fixed with line-by-line streaming for files >1MB, 50MB cap, and 8x parallel concurrency. Result: 141s -> 16.7s for 2,690 files. | Phase 2 | Fixed |
| BUG-011 | High | `updateFileState` in state.ts recorded `new Date().toISOString()` (scan wall-clock time) as `lastModified` instead of the file's actual `stat.mtime`. The incremental skip logic in scanner.ts compares `stat.mtime.toISOString()` against the stored `lastModified`, so the comparison always fails and every file is re-scanned on every `--incremental` run. Fixed by passing `stat.mtime` through to `updateFileState`. | Phase 2 | Fixed |
| BUG-012 | Medium | `loadScanState` validation accepted arrays as the `files` field because `typeof [] === "object"` and `[] !== null` both pass. A corrupted or adversarial state file with `{"lastScan":"...","files":[]}` would be loaded, causing runtime errors when the code indexes it as a `Record<string, FileState>`. Fixed by adding `Array.isArray(parsed.files)` rejection. | Phase 2 | Fixed |
| BUG-013 | Medium | `loadScanState` did not handle truncated/empty state files explicitly, but the existing try/catch around JSON.parse covered this case. Added tests to verify graceful handling of zero-byte files and truncated JSON fragments. | Phase 2 | Verified |
| BUG-014 | Low | Discovery variant matching verified correct: directories like `.claudebot` or `.codextra` (no separator after prefix) are correctly rejected. Only exact matches or prefix + separator (-, ., _) are accepted. Added regression tests. | Phase 2 | Verified |
| BUG-015 | Low | `.shhhignore` parsing handles Windows CRLF line endings correctly (via `.trim()`), binary content without crashing, and colons in type values. Added tests for these edge cases. | Phase 2 | Verified |
| BUG-016 | Medium | Incremental JSONL scans reported wrong line numbers when resuming from a byte offset. `lineNumber` started at 0 regardless of how many lines were previously scanned, so findings from appended content would report line 1 instead of the correct absolute line. Fixed by storing `linesScanned` in `FileState` and using it as the starting offset for `lineNumber` when resuming. | Phase 2 | Fixed |
| BUG-017 | High | `detectContextType` in `scoring.ts` only checked for `"role":"assistant"` (no space) but not `"role": "assistant"` (with space after colon). The `"user"` check correctly handled both variants. This caused assistant-context secrets in space-formatted JSON to be misclassified as `"unknown"` instead of `"ai_output"`, resulting in a score 5 points lower than correct (missing the "AI echoed secret back" risk factor). Fixed by adding the spaced variant check. | Phase 3 | Fixed |
| BUG-018 | Medium | `detectContextType` in `scoring.ts` only checked for `"type":"tool_result"` (no space) but not `"type": "tool_result"` (with space after colon). Tool results in space-formatted JSON were misclassified as `"unknown"` instead of `"tool_result"`, causing a score 10 points lower than correct (missing the "Tool exposed secret" risk factor). Fixed by adding the spaced variant check. | Phase 3 | Fixed |
