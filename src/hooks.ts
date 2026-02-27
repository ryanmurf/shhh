import {
  existsSync,
  readFileSync,
  writeFileSync,
  chmodSync,
  mkdirSync,
} from "node:fs";
import { join, resolve } from "node:path";

/**
 * Supported git hook types.
 */
export type HookType = "pre-commit" | "pre-push";

/**
 * Marker comments used to identify shhh-managed hook sections.
 */
const HOOK_START_MARKER = "# >>> shhh secret scanner >>>";
const HOOK_END_MARKER = "# <<< shhh secret scanner <<<";

/**
 * Generate the shell script snippet that shhh injects into git hooks.
 */
function generateHookScript(): string {
  return `${HOOK_START_MARKER}
# Runs shhh to scan for leaked secrets before proceeding.
# If secrets are found (exit code 2), the operation is blocked.
if command -v shhh >/dev/null 2>&1; then
  SHHH_CMD="shhh"
elif command -v npx >/dev/null 2>&1; then
  SHHH_CMD="npx shhh"
else
  echo "shhh: warning: shhh is not installed and npx is not available. Skipping secret scan."
  exit 0
fi

$SHHH_CMD scan --format json > /dev/null 2>&1
SHHH_EXIT=$?

if [ $SHHH_EXIT -eq 2 ]; then
  echo ""
  echo "shhh: Secrets detected! Commit/push blocked."
  echo "Run 'shhh scan' for details, or use --no-verify to bypass."
  exit 1
fi
${HOOK_END_MARKER}`;
}

/**
 * Resolve the .git/hooks directory for the given project directory.
 * Throws if .git does not exist.
 */
function resolveHooksDir(projectDir: string): string {
  const gitDir = join(projectDir, ".git");
  if (!existsSync(gitDir)) {
    throw new Error(
      `No .git directory found in ${projectDir}. Are you in a git repository?`,
    );
  }
  return join(gitDir, "hooks");
}

/**
 * Install a shhh git hook that scans for secrets before allowing the
 * git operation to proceed.
 *
 * If the hook file already exists, shhh appends its section (identified
 * by marker comments) without replacing existing hook logic. If the shhh
 * section is already present, the install is a no-op.
 *
 * @param hookType - The git hook to install ("pre-commit" or "pre-push")
 * @param projectDir - The root of the git repository (defaults to cwd)
 */
export function installHook(
  hookType: HookType,
  projectDir?: string,
): void {
  const dir = resolve(projectDir ?? process.cwd());
  const hooksDir = resolveHooksDir(dir);

  // Ensure the hooks directory exists (it may not in a fresh git init)
  mkdirSync(hooksDir, { recursive: true });

  const hookPath = join(hooksDir, hookType);
  const hookScript = generateHookScript();

  if (existsSync(hookPath)) {
    const existingContent = readFileSync(hookPath, "utf-8");

    // Already installed — no-op
    if (existingContent.includes(HOOK_START_MARKER)) {
      return;
    }

    // Append to existing hook
    const updatedContent = existingContent + "\n\n" + hookScript + "\n";
    writeFileSync(hookPath, updatedContent, "utf-8");
  } else {
    // Create new hook file with shebang
    const newContent = "#!/bin/sh\n\n" + hookScript + "\n";
    writeFileSync(hookPath, newContent, "utf-8");
  }

  // Make the hook executable
  chmodSync(hookPath, 0o755);
}

/**
 * Remove the shhh section from a git hook.
 *
 * Only the shhh-managed section (between the marker comments) is removed.
 * The rest of the hook file is preserved. If the hook file becomes empty
 * (only shebang + whitespace), it is left in place but still functional.
 *
 * @param hookType - The git hook to uninstall ("pre-commit" or "pre-push")
 * @param projectDir - The root of the git repository (defaults to cwd)
 */
export function uninstallHook(
  hookType: HookType,
  projectDir?: string,
): void {
  const dir = resolve(projectDir ?? process.cwd());
  const hooksDir = resolveHooksDir(dir);
  const hookPath = join(hooksDir, hookType);

  if (!existsSync(hookPath)) {
    return;
  }

  const content = readFileSync(hookPath, "utf-8");

  if (!content.includes(HOOK_START_MARKER)) {
    // shhh section not present — nothing to do
    return;
  }

  // Remove the shhh section and any surrounding blank lines
  const startIdx = content.indexOf(HOOK_START_MARKER);
  const endIdx = content.indexOf(HOOK_END_MARKER);

  if (startIdx === -1 || endIdx === -1) {
    return;
  }

  const before = content.slice(0, startIdx);
  const after = content.slice(endIdx + HOOK_END_MARKER.length);

  // Clean up extra blank lines at the junction
  const cleaned = (before + after).replace(/\n{3,}/g, "\n\n").trimEnd() + "\n";

  writeFileSync(hookPath, cleaned, "utf-8");
}
