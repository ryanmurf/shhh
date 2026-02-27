#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { Command } from "commander";
import { scanAll, scanPlatform } from "./scanner.js";
import { formatText, formatJson, formatSarif, formatDashboard } from "./reporter.js";
import { loadScanState, saveScanState, deleteScanState, getStateFilePath } from "./state.js";
import { watchSessions } from "./watcher.js";
import { loadCustomRules } from "./rules.js";
import { redactFindings } from "./redactor.js";
import { scoreFindings } from "./scoring.js";
import { installHook, uninstallHook } from "./hooks.js";
import type { Platform } from "./types.js";
import type { HookType } from "./hooks.js";

const VALID_PLATFORMS = ["claude", "codex", "copilot"] as const;
const VALID_FORMATS = ["text", "json", "sarif", "dashboard"] as const;

const program = new Command();

program
  .name("shhh")
  .description(
    "Scan AI coding assistant session files for leaked secrets. " +
      "Supports Claude Code, OpenAI Codex CLI, and GitHub Copilot CLI.",
  )
  .version("0.1.0");

program
  .command("scan")
  .description("Scan session files for secrets")
  .option(
    "-p, --platform <platform>",
    "Platform to scan (claude, codex, copilot). Scans all if omitted.",
  )
  .option(
    "-f, --format <format>",
    "Output format (text, json, sarif, dashboard)",
    "text",
  )
  .option(
    "--no-ignore",
    "Disable .shhhignore processing",
  )
  .option(
    "-i, --incremental",
    "Enable incremental scanning (only scan new/changed content)",
  )
  .option(
    "--scored",
    "Enable severity scoring with context analysis on findings",
  )
  .action(async (options: { platform?: string; format: string; ignore: boolean; incremental?: boolean; scored?: boolean }) => {
    // Validate platform
    if (
      options.platform &&
      !VALID_PLATFORMS.includes(options.platform as Platform)
    ) {
      console.error(
        `Error: Invalid platform "${options.platform}". ` +
          `Valid options: ${VALID_PLATFORMS.join(", ")}`,
      );
      process.exit(1);
    }

    // Validate format
    if (!VALID_FORMATS.includes(options.format as (typeof VALID_FORMATS)[number])) {
      console.error(
        `Error: Invalid format "${options.format}". ` +
          `Valid options: ${VALID_FORMATS.join(", ")}`,
      );
      process.exit(1);
    }

    try {
      // Commander's --no-ignore flag sets options.ignore to false when used
      const scanState = options.incremental ? loadScanState() : undefined;
      const scanOptions = { noIgnore: !options.ignore, scanState };
      const result = options.platform
        ? await scanPlatform(options.platform as Platform, scanOptions)
        : await scanAll(scanOptions);

      // Persist updated incremental state after a successful scan
      if (scanState) {
        scanState.lastScan = new Date().toISOString();
        saveScanState(scanState);
      }

      // Post-process: apply severity scoring if --scored flag is set
      if (options.scored && result.findings.length > 0) {
        const lineCache = new Map<string, string[]>();
        const getLineContent = (filePath: string, line: number): string => {
          if (!lineCache.has(filePath)) {
            try {
              lineCache.set(filePath, readFileSync(filePath, "utf-8").split("\n"));
            } catch {
              lineCache.set(filePath, []);
            }
          }
          const lines = lineCache.get(filePath)!;
          return lines[line - 1] ?? "";
        };
        result.findings = scoreFindings(result.findings, getLineContent);
      }

      let output: string;
      switch (options.format) {
        case "json":
          output = formatJson(result);
          break;
        case "sarif":
          output = formatSarif(result);
          break;
        case "dashboard":
          output = formatDashboard(result);
          break;
        default:
          output = formatText(result);
          break;
      }

      console.log(output);

      // Exit with non-zero code if secrets were found
      if (result.findings.length > 0) {
        process.exit(2);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Error during scan: ${message}`);
      process.exit(1);
    }
  });

program
  .command("clean")
  .description("Delete the incremental scan state file (resets incremental scanning)")
  .action(() => {
    const deleted = deleteScanState();
    if (deleted) {
      console.log(`Scan state deleted: ${getStateFilePath()}`);
    } else {
      console.log("No scan state file found. Nothing to clean.");
    }
  });

program
  .command("watch")
  .description("Watch session directories for new secrets in real-time")
  .option(
    "-p, --platform <platform>",
    "Platform to watch (claude, codex, copilot). Watches all if omitted.",
  )
  .action((options: { platform?: string }) => {
    // Validate platform
    if (
      options.platform &&
      !VALID_PLATFORMS.includes(options.platform as Platform)
    ) {
      console.error(
        `Error: Invalid platform "${options.platform}". ` +
          `Valid options: ${VALID_PLATFORMS.join(", ")}`,
      );
      process.exit(1);
    }

    const customRules = loadCustomRules();

    watchSessions({
      platform: options.platform as Platform | undefined,
      customRules: customRules.length > 0 ? customRules : undefined,
    });
  });

program
  .command("redact")
  .description("Scan for secrets and redact them in-place")
  .option(
    "-p, --platform <platform>",
    "Platform to scan (claude, codex, copilot). Scans all if omitted.",
  )
  .option(
    "--dry-run",
    "Show what would be redacted without modifying files",
  )
  .option(
    "--no-backup",
    "Do not create .bak backup files before modifying",
  )
  .action(async (options: { platform?: string; dryRun?: boolean; backup: boolean }) => {
    // Validate platform
    if (
      options.platform &&
      !VALID_PLATFORMS.includes(options.platform as Platform)
    ) {
      console.error(
        `Error: Invalid platform "${options.platform}". ` +
          `Valid options: ${VALID_PLATFORMS.join(", ")}`,
      );
      process.exit(1);
    }

    try {
      // First, run a scan to find secrets
      const scanOptions = { noIgnore: false };
      const result = options.platform
        ? await scanPlatform(options.platform as Platform, scanOptions)
        : await scanAll(scanOptions);

      if (result.findings.length === 0) {
        console.log("No secrets found. Nothing to redact.");
        return;
      }

      const dryRun = options.dryRun ?? false;
      const backup = options.backup;

      if (dryRun) {
        // Show findings and dry-run summary
        const output = formatText(result);
        console.log(output);

        // Count unique files
        const uniqueFiles = new Set(result.findings.map((f) => f.filePath));
        console.log(
          `Would redact ${result.findings.length} secrets in ${uniqueFiles.size} files`,
        );
        return;
      }

      // Apply redaction
      const redactResult = redactFindings(result.findings, { dryRun: false, backup });

      if (redactResult.errors.length > 0) {
        for (const err of redactResult.errors) {
          console.error(`  Error: ${err}`);
        }
      }

      if (backup) {
        console.log(
          `Redacted ${redactResult.secretsRedacted} secrets in ${redactResult.filesModified} files. Backups saved as *.bak`,
        );
      } else {
        console.log(
          `Redacted ${redactResult.secretsRedacted} secrets in ${redactResult.filesModified} files.`,
        );
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Error during redaction: ${message}`);
      process.exit(1);
    }
  });

// Hook management commands
const hookCommand = program
  .command("hook")
  .description("Manage git hook integration for secret scanning");

hookCommand
  .command("install")
  .description("Install a git hook that scans for secrets before commit/push")
  .option(
    "-t, --type <hookType>",
    "Hook type to install (pre-commit or pre-push)",
    "pre-commit",
  )
  .action((options: { type: string }) => {
    const validTypes = ["pre-commit", "pre-push"];
    if (!validTypes.includes(options.type)) {
      console.error(
        `Error: Invalid hook type "${options.type}". Valid options: ${validTypes.join(", ")}`,
      );
      process.exit(1);
    }

    try {
      installHook(options.type as HookType);
      console.log(`shhh ${options.type} hook installed successfully.`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Error installing hook: ${message}`);
      process.exit(1);
    }
  });

hookCommand
  .command("uninstall")
  .description("Remove the shhh git hook")
  .option(
    "-t, --type <hookType>",
    "Hook type to uninstall (pre-commit or pre-push)",
    "pre-commit",
  )
  .action((options: { type: string }) => {
    const validTypes = ["pre-commit", "pre-push"];
    if (!validTypes.includes(options.type)) {
      console.error(
        `Error: Invalid hook type "${options.type}". Valid options: ${validTypes.join(", ")}`,
      );
      process.exit(1);
    }

    try {
      uninstallHook(options.type as HookType);
      console.log(`shhh ${options.type} hook uninstalled successfully.`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Error uninstalling hook: ${message}`);
      process.exit(1);
    }
  });

program
  .command("version")
  .description("Show version information")
  .action(() => {
    console.log("shhh v0.1.0");
  });

program.parse();
