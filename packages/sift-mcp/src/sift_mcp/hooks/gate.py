"""Policy gate — harness-agnostic adapter for agent hook systems.

Called by agent harness hooks (Claude Code, OpenCode, Pi) to evaluate a
proposed command against the OPA policy engine before execution AND, when
the sandbox layer is enabled, to wrap allowed commands in a bubblewrap
namespace so every bash command gets kernel-level evidence protection —
not just those routed through ``run_command``.

Exit protocol
-------------
exit 0  = allowed (stdout may contain JSON with a rewritten command)
exit 2  = denied  (stderr contains the denial reasons)

Output protocol (stdout JSON, only when sandbox wrapping is active)
-------------------------------------------------------------------
The gate detects which harness invoked it from the input format and emits
the corresponding rewrite envelope:

Claude Code (PreToolUse, invoked directly by the hook system):
    stdout: {"hookSpecificOutput": {"hookEventName": "PreToolUse",
             "permissionDecision": "allow",
             "updatedInput": {"command": "bwrap ... -- /bin/bash -c '...'"}}}

OpenCode / Pi / generic (invoked by a TypeScript adapter via subprocess):
    stdout: {"command": "bwrap ... -- /bin/bash -c '...'"}

When sandbox wrapping is disabled or unavailable, exit 0 with no stdout
(bare allow, same as the pre-sandbox gate behavior).

Supported harnesses
-------------------

Claude Code (PreToolUse, matcher: Bash):
    stdin: JSON {"tool_input": {"command": "find /evidence -exec ..."}}
    exit 0 = no objection (normal permission flow continues)
    exit 2 = block execution (stderr = denial reason shown to agent)

OpenCode (tool.execute.before via TypeScript plugin):
    stdin: JSON {"command": "find /evidence -exec ..."}
    exit 0 = allow (stdout JSON parsed by plugin for command rewrite)
    exit 2 = block (stderr = reason, plugin throws Error)

Pi / oh-my-pi (tool_call via TypeScript extension):
    stdin: JSON {"command": "find /evidence -exec ..."}
    exit 0 = allow (stdout JSON parsed by extension for input mutation)
    exit 2 = block (extension returns {block: true, reason: ...})

Generic / fallback:
    argv[1:] = the command as separate arguments
    exit 0 = allow
    exit 2 = block (stderr = reason)
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from typing import NamedTuple


# ── input parsing ─────────────────────────────────────────────────────────────


class ParsedInput(NamedTuple):
    """Result of parsing the hook invocation."""

    raw: str  # original command string (for bash -c wrapping)
    argv: list[str]  # shlex-split command (for OPA + bwrap mount construction)
    source: str  # "claude-code" | "opencode" | "pi" | "generic"


def _parse_input() -> ParsedInput | None:
    """Extract the command from whichever harness invoked us.

    Returns a ParsedInput with the original string preserved (needed for
    bash -c wrapping) and a source tag so the output envelope matches the
    harness protocol.

    Detection order:
    1. stdin is a pipe with JSON → parse as Claude Code or adapter format
    2. OPENCODE_TOOL_ARGS env var → parse as OpenCode format
    3. argv[1:] is non-empty → treat as the command directly
    4. None → nothing to evaluate
    """
    # 1. stdin JSON
    if not sys.stdin.isatty():
        try:
            raw = sys.stdin.read().strip()
            if raw:
                data = json.loads(raw)

                # Claude Code format: {"tool_input": {"command": "..."}}
                if "tool_input" in data:
                    cmd_str = data["tool_input"].get("command", "")
                    if cmd_str:
                        return ParsedInput(cmd_str, shlex.split(cmd_str), "claude-code")

                # Adapter / OpenCode format: {"command": "..."}
                if "command" in data:
                    cmd_str = data["command"]
                    if isinstance(cmd_str, str) and cmd_str:
                        return ParsedInput(cmd_str, shlex.split(cmd_str), "adapter")

                # Nested format: {"tool_args": {"command": "..."}}
                if "tool_args" in data:
                    cmd_str = data["tool_args"].get("command", "")
                    if cmd_str:
                        return ParsedInput(cmd_str, shlex.split(cmd_str), "adapter")
        except (json.JSONDecodeError, ValueError):
            pass

    # 2. OpenCode env var
    oc_args = os.environ.get("OPENCODE_TOOL_ARGS", "")
    if oc_args:
        try:
            data = json.loads(oc_args)
            cmd_str = data.get("command", "")
            if cmd_str:
                return ParsedInput(cmd_str, shlex.split(cmd_str), "opencode")
        except (json.JSONDecodeError, ValueError):
            pass

    # 3. argv
    if len(sys.argv) > 1:
        cmd_str = " ".join(sys.argv[1:])
        return ParsedInput(cmd_str, list(sys.argv[1:]), "generic")

    return None


# ── sandbox wrapping ──────────────────────────────────────────────────────────


def _build_sandboxed_command(parsed: ParsedInput) -> str | None:
    """Build a bwrap-wrapped command string, or None if sandboxing is unavailable.

    Uses the same modules as run_command's Layer 2: build_input_doc for path
    classification (evidence → ro, output → rw) and build_sandbox_prefix for
    the bwrap flag construction. The original shell command is preserved inside
    ``bash -c`` so pipes, redirections, and compound commands work inside the
    namespace.

    Returns None (and logs a warning) on any error — the gate fails open on
    sandbox construction failures, same as it does on policy engine errors.
    """
    try:
        from sift_mcp.config import get_config, resolve_case_dir
        from sift_mcp.policy.parser import build_input_doc
        from sift_mcp.sandbox.bwrap import build_sandbox_prefix, load_profile

        cfg = get_config()
        if not cfg.sandbox_enabled:
            return None

        doc = build_input_doc(parsed.argv)
        prefix = build_sandbox_prefix(
            input_paths=doc["paths"],
            output_paths=doc["output_paths"],
            device_paths=doc["device_paths"],
            case_dir=resolve_case_dir() or None,
            profile=load_profile(cfg.sandbox_profile),
            bwrap_path=cfg.bwrap_path,
        )
        # prefix ends with "--"; append bash -c '<original command>'
        # shlex.quote handles embedded quotes, newlines, etc.
        return " ".join(prefix) + " /bin/bash -c " + shlex.quote(parsed.raw)

    except ImportError as exc:
        print(
            f"warning: sandbox modules not available: {exc}",
            file=sys.stderr,
        )
        return None
    except Exception as exc:
        print(
            f"warning: sandbox wrapping failed (fail-open): {exc}",
            file=sys.stderr,
        )
        return None


def _emit_rewrite(parsed: ParsedInput, wrapped_cmd: str) -> None:
    """Write the harness-appropriate JSON rewrite envelope to stdout."""
    if parsed.source == "claude-code":
        # Claude Code reads hookSpecificOutput directly from hook stdout
        envelope = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "Policy allowed; sandboxed via bwrap",
                "updatedInput": {"command": wrapped_cmd},
            }
        }
    else:
        # OpenCode plugin / Pi extension / generic adapter parse this JSON
        envelope = {"command": wrapped_cmd, "sandboxed": True}

    print(json.dumps(envelope))


# ── audit helpers ─────────────────────────────────────────────────────────────


def _audit_denial(command: list[str], decision: dict) -> None:
    """Best-effort: append a denial entry to the case audit trail.

    Mirrors the run_command denial record but tags ``source="harness_hook"`` so
    the trail shows the command was intercepted at the harness layer (the
    agent's native shell), not via the MCP run_command path.  No-ops silently if
    the audit writer is unavailable or no case is active — a pre-execution hook
    must never crash or alter its verdict because of an audit-write failure.
    """
    try:
        from sift_mcp.audit import AuditWriter

        AuditWriter(mcp_name="sift-mcp").log(
            tool="bash",
            params={"command": command, "purpose": "harness pre-execution hook"},
            result_summary={
                "error": "Command denied by policy: "
                + "; ".join(decision.get("reasons", [])),
                "policy_decision": {
                    "allowed": False,
                    "reasons": decision.get("reasons", []),
                    "policies_evaluated": decision.get("policies_evaluated", []),
                },
            },
            source="harness_hook",
        )
    except Exception:  # noqa: BLE001 — never let auditing break the gate
        pass


def _audit_sandbox_allow(command: list[str], wrapped_cmd: str) -> None:
    """Best-effort: log that a command was allowed and sandbox-wrapped.

    Captures the full bwrap command line so the audit trail shows both the
    policy decision (allow) and the sandbox flags used — symmetric with the
    run_command allow path, which records sandbox_args in the result.
    """
    try:
        from sift_mcp.audit import AuditWriter

        AuditWriter(mcp_name="sift-mcp").log(
            tool="bash",
            params={"command": command, "purpose": "harness pre-execution hook"},
            result_summary={
                "sandboxed": True,
                "wrapped_command": wrapped_cmd,
                "policy_decision": {"allowed": True},
            },
            source="harness_hook",
        )
    except Exception:  # noqa: BLE001
        pass


# ── main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    """Evaluate a command against the OPA policy engine.

    Returns:
        0 if allowed (or if the policy engine is unavailable — fail-open
          so forensic work is not blocked by a misconfigured hook).
          Stdout may contain a JSON rewrite envelope when sandbox wrapping
          is active.
        2 if denied (stderr contains the structured denial reasons).
    """
    parsed = _parse_input()
    if not parsed:
        # Nothing to evaluate — allow (no-op).
        return 0

    try:
        from sift_mcp.config import get_config
        from sift_mcp.policy.evaluator import evaluate_command
    except ImportError:
        # sift_mcp not installed or not on PYTHONPATH — fail open.
        print(
            "warning: sift_mcp.policy not available, skipping policy check",
            file=sys.stderr,
        )
        return 0

    # Respect the same SIFT_POLICY_ENGINE toggle as Layer 1 (run_command). When
    # the policy engine is disabled, this hook is a no-op — enforcement stays
    # consistent across the MCP path and the harness-hook path.
    cfg = get_config()
    if not cfg.policy_engine_enabled:
        # Policy disabled but sandbox may still be enabled independently.
        # In that case, wrap the command even without policy evaluation.
        if cfg.sandbox_enabled:
            wrapped = _build_sandboxed_command(parsed)
            if wrapped:
                _audit_sandbox_allow(parsed.argv, wrapped)
                _emit_rewrite(parsed, wrapped)
        return 0

    # Decompose the shell line into its constituent simple commands so EACH is
    # policy-checked on its own. A dangerous command hidden after an operator
    # (``a && rm -rf /evidence``) or inside a substitution (``$(rm ...)``) is
    # caught at Layer 1 here — not left solely to the Layer 2 sandbox. Falls
    # back to the whole command on any decomposition trouble.
    try:
        from sift_mcp.hooks.shell_decompose import decompose_command_line

        subcommands = decompose_command_line(parsed.raw) or [parsed.argv]
    except Exception:  # noqa: BLE001 — decomposition must never break the gate
        subcommands = [parsed.argv]

    for sub in subcommands:
        try:
            # Tag as the harness-hook source: each sub-command is a real
            # [tool, *args] with operators removed, but a word may still carry
            # a substitution token ($(...)); the shell_metacharacters rule is
            # scoped out for this source so that isn't a false positive. Every
            # other rule (rm_protection, denied_binaries, path policy) applies.
            decision = evaluate_command(sub, context_extra={"source": "harness_hook"})
        except Exception as exc:
            # Policy engine error — fail open for this sub-command (same
            # behavior as run_command), and keep checking the rest.
            print(f"warning: policy engine error: {exc}", file=sys.stderr)
            continue

        if not decision.get("allowed", False):
            # Denied — audit, surface reasons, block the whole line.
            _audit_denial(sub, decision)
            reasons = decision.get("reasons", ["command denied by policy"])
            deny_msg = "Policy denial: " + "; ".join(reasons)
            print(deny_msg, file=sys.stderr)
            return 2

    # Allowed — wrap in bwrap sandbox if enabled, then emit rewrite envelope.
    wrapped = _build_sandboxed_command(parsed)
    if wrapped:
        _audit_sandbox_allow(parsed.argv, wrapped)
        _emit_rewrite(parsed, wrapped)
    # else: no sandbox — bare exit 0 (allow without modification)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())