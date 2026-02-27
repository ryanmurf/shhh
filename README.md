# shhh-scan

[![npm version](https://img.shields.io/npm/v/shhh-scan)](https://www.npmjs.com/package/shhh-scan)
[![CI](https://github.com/ryanmurf/shhh/actions/workflows/ci.yml/badge.svg)](https://github.com/ryanmurf/shhh/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Scan AI coding assistant sessions for leaked secrets.

---

## Why

AI coding assistants like Claude Code, Codex CLI, and Copilot CLI store session logs on your machine. These logs capture your full conversation history, including any secrets you pasted, environment variables that appeared in tool output, and credentials embedded in config files the assistant read. Those secrets sit on disk in plaintext, often in locations you never think to audit.

shhh finds them. It scans session files across all major AI assistant platforms, detects 20+ secret types using pattern matching and entropy analysis, and gives you the tools to redact, monitor, and prevent leaks.

## Install

```bash
npm install -g shhh-scan
```

Requires Node.js 18 or later.

## Quick Start

Scan all platforms for leaked secrets:

```
shhh scan
```

Scan only Claude Code sessions:

```
shhh scan --platform claude
```

View results as a rich terminal dashboard:

```
shhh scan --format dashboard
```

Get context-aware severity scores for each finding:

```
shhh scan --scored
```

## Supported Platforms

| Platform | Base Directory | Variants Auto-Discovered |
|---|---|---|
| **Claude Code** | `~/.claude/` | `~/.claude-dev`, `~/.claude-work`, etc. |
| **Codex CLI** | `~/.codex/` | `~/.codex-beta`, `~/.codex-*` |
| **Copilot CLI** | `~/.copilot/`, `~/.config/github-copilot/` | `~/.copilot-*` |

Variant directories are discovered automatically. Any directory in your home folder matching the platform prefix followed by a separator (`-`, `.`, `_`) is included. For example, `~/.claude-dev` and `~/.codex-nightly` are picked up without any configuration.

## Commands

### `shhh scan`

Scan session files for secrets across all supported platforms.

```
shhh scan [options]
```

**Options:**

| Flag | Description |
|---|---|
| `-p, --platform <platform>` | Scan a single platform: `claude`, `codex`, or `copilot`. Scans all if omitted. |
| `-f, --format <format>` | Output format: `text` (default), `json`, `sarif`, or `dashboard`. |
| `--scored` | Enable context-aware severity scoring. Adds a numeric risk score (0-100), context type, and risk factors to each finding. |
| `-i, --incremental` | Only scan new or changed content since the last scan. Tracks file positions to avoid re-scanning unchanged data. |
| `--no-ignore` | Disable `.shhhignore` processing. All findings are reported regardless of ignore rules. |

**Examples:**

```bash
# Scan everything, default text output
shhh scan

# Scan only Codex sessions, output as JSON
shhh scan --platform codex --format json

# SARIF output for CI integration
shhh scan --format sarif > results.sarif

# Incremental scan with severity scores
shhh scan --incremental --scored

# Dashboard view
shhh scan --format dashboard
```

**Exit codes:**

- `0` -- No secrets found.
- `2` -- One or more secrets detected.
- `1` -- An error occurred during scanning.

---

### `shhh watch`

Monitor session directories in real time. As AI assistants write new session data, shhh detects secrets as they appear.

```
shhh watch [options]
```

**Options:**

| Flag | Description |
|---|---|
| `-p, --platform <platform>` | Watch a single platform. Watches all if omitted. |

**Example:**

```bash
# Watch all platforms
shhh watch

# Watch only Claude Code sessions
shhh watch --platform claude
```

---

### `shhh redact`

Scan for secrets and replace them in-place with redacted values. By default, backup files (`.bak`) are created before modifying any file.

```
shhh redact [options]
```

**Options:**

| Flag | Description |
|---|---|
| `-p, --platform <platform>` | Scan a single platform. Scans all if omitted. |
| `--dry-run` | Show what would be redacted without modifying any files. |
| `--no-backup` | Skip creating `.bak` backup files before modifying. |

**Examples:**

```bash
# Preview what would be redacted
shhh redact --dry-run

# Redact all secrets with backups
shhh redact

# Redact without creating backup files
shhh redact --no-backup

# Redact only Copilot session secrets
shhh redact --platform copilot
```

---

### `shhh hook install` / `shhh hook uninstall`

Install or remove a git hook that runs shhh before commits or pushes. If secrets are detected, the hook blocks the operation.

```
shhh hook install [options]
shhh hook uninstall [options]
```

**Options:**

| Flag | Description |
|---|---|
| `-t, --type <hookType>` | Hook type: `pre-commit` (default) or `pre-push`. |

**Examples:**

```bash
# Install a pre-commit hook
shhh hook install

# Install a pre-push hook instead
shhh hook install --type pre-push

# Remove the pre-commit hook
shhh hook uninstall

# Remove a pre-push hook
shhh hook uninstall --type pre-push
```

---

### `shhh clean`

Delete the incremental scan state file. This resets incremental scanning so the next `--incremental` scan processes all files from scratch.

```
shhh clean
```

## Output Formats

### `text` (default)

Colorized terminal output with a severity summary and detailed findings. Each finding shows the secret type, file location, platform, a redacted match, and surrounding context.

### `json`

Structured JSON containing the full scan result: findings array, files scanned, platforms scanned, and scan duration. When `--scored` is used, each finding includes `score`, `contextType`, and `riskFactors` fields.

### `sarif`

SARIF 2.1.0 (Static Analysis Results Interchange Format) output for integration with CI systems, GitHub Code Scanning, and other tools that consume SARIF.

### `dashboard`

A rich terminal dashboard rendered with unicode box-drawing characters, including severity bar charts, top secret types, and a platform breakdown. Designed for a quick visual overview.

## Configuration

### `.shhhignore`

Create a `.shhhignore` file to suppress known-safe findings. shhh looks for this file in two locations (rules from both are merged):

1. The current working directory (`./.shhhignore`)
2. The global config directory (`~/.config/shhh/.shhhignore`)

**Format:**

```
# Lines starting with # are comments
# Blank lines are ignored

# Literal strings -- suppress findings whose match or context contains this value
AKIAIOSFODNN7EXAMPLE

# type: prefix -- suppress all findings of a given secret type
type:High-Entropy String
type:Generic API Key

# file: glob -- suppress findings from files matching a glob pattern
file:**/test-sessions/**
file:/home/user/.claude/archive/**

# platform: name -- suppress all findings from an entire platform
platform:copilot
```

**Rule types:**

| Prefix | Behavior |
|---|---|
| *(none)* | Literal string match against the finding's redacted match or context |
| `type:` | Suppress findings whose `secretType` starts with this value (case-insensitive) |
| `file:` | Suppress findings from files matching this glob pattern |
| `platform:` | Suppress all findings from the named platform |

---

### `~/.config/shhh/rules.json`

Define custom detection rules to supplement the 20+ built-in patterns. The file must contain a JSON array of rule objects.

**Format:**

```json
[
  {
    "name": "Stripe Secret Key",
    "pattern": "sk_live_[A-Za-z0-9]{24,}",
    "severity": "critical"
  },
  {
    "name": "SendGrid API Key",
    "pattern": "SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}",
    "severity": "high"
  },
  {
    "name": "Internal Service Token",
    "pattern": "svc_tok_[a-f0-9]{32}",
    "severity": "medium"
  }
]
```

**Fields:**

| Field | Type | Description |
|---|---|---|
| `name` | string | Descriptive name for the rule (appears in findings as `secretType`) |
| `pattern` | string | Regular expression pattern (compiled with the global flag) |
| `severity` | string | One of: `critical`, `high`, `medium`, `low` |

Invalid rules (malformed regex, missing fields) are skipped with a warning to stderr.

## Secret Types Detected

shhh includes 20+ built-in detection patterns covering the most common secret types, plus a high-entropy string detector for catching unknown or unusual credentials.

### Cloud Credentials

| Pattern | Severity |
|---|---|
| AWS Access Key ID | Critical |
| AWS Secret Access Key | Critical |

### Source Control Tokens

| Pattern | Severity |
|---|---|
| GitHub Personal Access Token (`ghp_`) | High |
| GitHub OAuth Token (`gho_`) | High |
| GitHub Server Token (`ghs_`) | High |
| GitHub Refresh Token (`ghr_`) | High |
| GitHub Fine-Grained PAT (`github_pat_`) | High |

### Messaging Tokens

| Pattern | Severity |
|---|---|
| Slack Bot Token (`xoxb-`) | High |
| Slack User Token (`xoxp-`) | High |
| Slack Secret Token (`xoxs-`) | High |

### Private Keys

| Pattern | Severity |
|---|---|
| RSA Private Key | Critical |
| EC Private Key | Critical |
| PGP Private Key | Critical |
| Generic Private Key | Critical |

### Database Connection Strings

| Pattern | Severity |
|---|---|
| PostgreSQL Connection String | High |
| MySQL Connection String | High |
| MongoDB Connection String | High |

### Authentication Tokens

| Pattern | Severity |
|---|---|
| JWT (JSON Web Token) | Medium |
| Bearer Token | Medium |

### Generic Patterns

| Pattern | Severity |
|---|---|
| Generic API Key (assignment) | Medium |
| High-Entropy String (Shannon entropy > 5.0) | Low |

### False-Positive Reduction

shhh applies multiple layers of filtering to minimize noise:

- **Placeholder detection** -- Values like `your-api-key-here`, `EXAMPLE`, `change-me`, and repeated characters (`xxxx...`) are excluded.
- **Entropy filtering** -- High-entropy detection uses a 5-layer context-aware filtering pipeline: raised threshold (5.0), max length cap (100 chars), context keyword skip, per-file cap (10 findings), and conversation line skip.
- **Custom suppression** -- Use `.shhhignore` rules or define patterns that match your environment.

## Severity Scoring

When `--scored` is enabled, each finding receives a numeric risk score from 0 to 100, a context type, and a list of risk factors.

**Context types:**

| Type | Description | Score Adjustment |
|---|---|---|
| `user_input` | Secret appeared in a user message | +15 |
| `config` | Secret found in a config/settings file | +20 |
| `tool_result` | Secret exposed by a tool result | +10 |
| `ai_output` | AI assistant echoed the secret | +5 |
| `unknown` | Context could not be determined | +0 |

**Additional factors:**

- Cloud credentials (AWS, GitHub) receive a +5 bonus.
- Secrets repeated across multiple locations receive up to +15.
- Archived or backup sessions receive a -10 discount.
- Likely test/example data receives a -20 discount.

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Lint
npm run lint
```

## License

Apache-2.0
