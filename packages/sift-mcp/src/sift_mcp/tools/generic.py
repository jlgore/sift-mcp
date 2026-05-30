"""Generic run_command: denylist-protected execution of forensic tools."""

from __future__ import annotations

import logging

from sift_mcp.catalog import get_tool_def
from sift_mcp.config import get_config
from sift_mcp.environment import find_binary
from sift_mcp.exceptions import (
    ExecutionError,
    PolicyDenialError,
    PolicyEngineError,
)
from sift_mcp.executor import execute
from sift_mcp.security import validate_command

logger = logging.getLogger(__name__)


def run_command(
    command: list[str],
    *,
    purpose: str = "",
    timeout: int | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
    cwd: str | None = None,
    preview_lines: int = 0,
) -> dict:
    """Execute a command if its binary is not on the denylist.

    Args:
        command: Command as list of strings.
        purpose: Reason for running (audit trail).
        timeout: Override timeout.
        save_output: Save stdout/stderr to files.
        save_dir: Directory for saved output.
        cwd: Working directory.

    Raises:
        DeniedBinaryError: Binary is on the hard denylist.
        ExecutionError: Binary not found on system.
    """
    if not command:
        raise ValueError("Empty command")

    # Layer 1: OPA policy evaluation (when enabled). Runs BEFORE security.py so
    # a denial returns ALL violation reasons at once. security.py still runs
    # afterwards as belt-and-suspenders on allow. If the engine itself errors
    # (misconfig, missing binary), fail through to security.py rather than
    # blocking forensic work — security.py remains a sound enforcement floor.
    if get_config().policy_engine_enabled:
        from sift_mcp.policy.evaluator import evaluate_command

        try:
            decision = evaluate_command(command)
        except PolicyEngineError as exc:
            logger.warning("Policy engine unavailable, using security.py only: %s", exc)
        else:
            if not decision.get("allowed", False):
                reasons = decision.get("reasons", [])
                raise PolicyDenialError(
                    "Command denied by policy: " + "; ".join(reasons), decision
                )

    # security.py validation gauntlet: denylist, rm protection, path
    # classification, flag/metacharacter/awk sanitization. Raises on violation.
    binary = validate_command(command)

    # Resolve binary via find_binary to prevent absolute path bypass
    resolved = find_binary(binary)
    if not resolved:
        raise ExecutionError(f"Binary '{binary}' not found on this system.")
    command = [resolved] + command[1:]

    # Layer 2: wrap the command in a bwrap sandbox (when enabled). Mounts are
    # derived from the same parsed paths the policy engine uses: input/device
    # paths -> read-only binds, output paths -> read-write binds.
    sandbox_prefix = None
    cfg_sb = get_config()
    if cfg_sb.sandbox_enabled:
        from sift_mcp.config import resolve_case_dir
        from sift_mcp.policy.parser import build_input_doc
        from sift_mcp.sandbox.bwrap import build_sandbox_prefix, load_profile

        doc = build_input_doc(command)
        sandbox_prefix = build_sandbox_prefix(
            input_paths=doc["paths"],
            output_paths=doc["output_paths"],
            device_paths=doc["device_paths"],
            case_dir=resolve_case_dir() or None,
            profile=load_profile(cfg_sb.sandbox_profile),
            bwrap_path=cfg_sb.bwrap_path,
        )

    exec_result = execute(
        command,
        timeout=timeout,
        cwd=cwd,
        save_output=save_output,
        save_dir=save_dir,
        sandbox_prefix=sandbox_prefix,
    )
    if sandbox_prefix is not None:
        exec_result["sandboxed"] = True
        exec_result["sandbox_profile"] = cfg_sb.sandbox_profile
        # Drop the trailing "--" for a compact record of the bwrap flags used.
        exec_result["sandbox_args"] = sandbox_prefix[1:-1]

    # Parse output based on catalog format when output exceeds byte budget
    cfg = get_config()
    stdout = exec_result.get("stdout", "")
    stdout_bytes = exec_result.get("stdout_total_bytes", len(stdout.encode("utf-8")))

    td = get_tool_def(binary)
    output_format = td.output_format if td else "text"

    # Small output — return as-is (no parsing overhead)
    if stdout_bytes <= cfg.response_byte_budget:
        exec_result["_output_format"] = output_format
        return exec_result

    # Large output — parse with byte budget
    from sift_common.parsers import csv_parser, json_parser, text_parser

    # If preview_lines requested, scale budget up (assume ~200 bytes/line)
    budget = (
        max(cfg.response_byte_budget, preview_lines * 200)
        if preview_lines
        else cfg.response_byte_budget
    )
    ml = preview_lines or 50000

    if output_format == "csv":
        csv_kwargs = {"byte_budget": budget}
        if preview_lines:
            csv_kwargs["max_rows"] = ml
        parsed = csv_parser.parse_csv(stdout, **csv_kwargs)
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_csv"
    elif output_format == "json":
        parsed = json_parser.parse_json(stdout, byte_budget=budget)
        if parsed.get("parse_error"):
            parsed = json_parser.parse_jsonl(stdout, byte_budget=budget)
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_json"
    else:
        parsed = text_parser.parse_text(stdout, byte_budget=budget, max_lines=ml)
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_text"

    # Replace raw stdout with None — full output is on disk if saved
    exec_result["stdout"] = None

    return exec_result
