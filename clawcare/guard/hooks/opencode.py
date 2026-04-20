"""OpenCode post-exec hook handler.

This module is invoked by the ClawCare Guard TypeScript plugin for OpenCode as
a subprocess::

    echo '{"tool":"bash","input":{"command":"..."},...}' | \\
      clawcare guard hook --platform opencode --stage post

The *pre*-command interception is handled entirely by the TypeScript plugin's
``tool.execute.before`` hook, which calls ``clawcare guard run -- <command>``
directly and throws to block.  This module only handles the **post-exec audit**
path.

See also:
  clawcare/guard/plugin_assets/opencode-plugin.ts  — the TS plugin source
  https://opencode.ai/docs/plugins/
"""

from __future__ import annotations

import contextlib
import json
import sys
from typing import Any

from clawcare.guard.audit import write_audit_event
from clawcare.guard.config import GuardConfig
from clawcare.guard.scanner import scan_command


def handle_post(config: GuardConfig) -> int:
    """Handle OpenCode post-execution audit event.

    Reads JSON from stdin (piped by the TypeScript plugin's
    ``tool.execute.after`` hook) and writes an audit log entry.
    """
    payload = _read_stdin_json()
    if payload is None:
        return 0

    command = _extract_command(payload) or ""
    post_verdict = scan_command(command, fail_on=config.fail_on) if command else None

    output = payload.get("output", {})
    exit_code: int | None = None

    if isinstance(output, dict):
        raw = output.get("exit_code") or output.get("exitCode")
        if raw is not None:
            with contextlib.suppress(ValueError, TypeError):
                exit_code = int(raw)

    if config.audit.enabled:
        write_audit_event(
            "post_exec",
            platform="opencode",
            command=command,
            status="executed",
            findings=[
                {"rule_id": f.rule_id, "severity": f.severity.name}
                for f in post_verdict.findings
            ] if post_verdict else [],
            exit_code=exit_code,
            log_path=config.audit.log_path,
            extra={"tool": payload.get("tool", "bash")},
        )

    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_command(payload: dict[str, Any]) -> str | None:
    """Extract command string from the plugin-provided payload."""
    inp = payload.get("input", {})
    if isinstance(inp, dict):
        cmd = inp.get("command") or inp.get("cmd")
        if isinstance(cmd, str):
            return cmd

    cmd = payload.get("command")
    if isinstance(cmd, str):
        return cmd
    return None


def _read_stdin_json() -> dict[str, Any] | None:
    """Read and parse JSON from stdin."""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return None
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
        return None
    except (json.JSONDecodeError, OSError):
        return None
