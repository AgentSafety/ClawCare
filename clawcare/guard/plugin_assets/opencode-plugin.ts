/**
 * ClawCare Guard — OpenCode plugin.
 *
 * Installed by `clawcare guard activate --platform opencode`
 * into `~/.config/opencode/plugins/clawcare-guard.ts` (global) or
 * `.opencode/plugins/clawcare-guard.ts` (project-level).
 *
 * At activation time the placeholder `__CLAWCARE_BIN__` is replaced with the
 * fully-resolved path to the `clawcare` binary (e.g.
 * `/opt/homebrew/Caskroom/miniconda/base/bin/clawcare`).  This ensures the
 * plugin works even when the binary is not on the default PATH (conda envs,
 * pyenv shims, etc.).
 *
 * Hooks registered:
 *   tool.execute.before  — pre-command scan; throws to block if ClawCare exits 2
 *   tool.execute.after   — post-exec audit logging via `clawcare guard hook`
 *
 * Reference:
 *   https://opencode.ai/docs/plugins/
 */

import { execSync } from "child_process";
import { existsSync } from "fs";

/** Resolved at activation time by `clawcare guard activate`. */
const CLAWCARE_BIN = "__CLAWCARE_BIN__";

function resolveBin(): string {
  if (CLAWCARE_BIN.startsWith("/") && !existsSync(CLAWCARE_BIN)) {
    console.warn(
      `[clawcare-guard] binary not found at ${CLAWCARE_BIN} — ` +
        "was it moved?  Re-run:  clawcare guard activate --platform opencode",
    );
  }
  return CLAWCARE_BIN;
}

function shellEscape(s: string): string {
  // Wrap in single quotes, escaping embedded single quotes.
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

function extractCommand(tool: string, args: any): string | undefined {
  // OpenCode's bash tool puts the command in args.command.
  const t = (tool ?? "").toLowerCase();
  if (t === "bash" || t === "shell" || t === "terminal") {
    return args?.command ?? args?.cmd ?? undefined;
  }
  // Fallback: try to find a command field for unknown tools.
  return args?.command ?? undefined;
}

export default async function (_ctx: any) {
  const bin = resolveBin();

  return {
    // ── tool.execute.before ─────────────────────────────────────────
    // Intercept tool calls before execution.  ClawCare scans the command and
    // exits 2 to block, 0 to allow.  Throwing here blocks the tool call in
    // OpenCode.
    "tool.execute.before": async (
      input: { tool: string; sessionID: string; callID: string },
      output: { args: any },
    ) => {
      const command = extractCommand(input.tool, output.args);
      if (!command) return;

      try {
        execSync(`${bin} guard run -- ${shellEscape(command)}`, {
          stdio: ["pipe", "pipe", "pipe"],
          timeout: 10_000,
        });
        // exit 0 → allow (no return value needed)
      } catch (err: any) {
        if (err.status === 2) {
          // ClawCare blocked the command — throw to block the tool call.
          const reason =
            err.stderr?.toString().trim() ||
            err.stdout?.toString().trim() ||
            "Blocked by ClawCare guard";
          throw new Error(reason);
        }
        // Non-2 error → log and allow (fail-open so ClawCare errors don't
        // break the agent entirely).
        console.warn(`[clawcare-guard] scan error: ${err.message}`);
      }
    },

    // ── tool.execute.after ───────────────────────────────────────────
    // Post-exec audit: pipe the command + output metadata to the ClawCare
    // Python hook handler so it can write an audit log entry.
    "tool.execute.after": async (
      input: { tool: string; sessionID: string; callID: string; args: any },
      output: { title: string; output: string; metadata: any },
    ) => {
      const command = extractCommand(input.tool, input.args);
      if (!command) return;

      try {
        const payload = JSON.stringify({
          tool: input.tool,
          input: { command },
          output: { output: output.output },
        });

        execSync(`${bin} guard hook --platform opencode --stage post`, {
          input: payload,
          stdio: ["pipe", "pipe", "pipe"],
          timeout: 5_000,
        });
      } catch {
        // Post-exec logging is best-effort; never block on audit failure.
      }
    },
  };
}
