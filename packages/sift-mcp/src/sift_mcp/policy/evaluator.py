"""OPA evaluation interface for run_command.

Compiles security.yaml once (lazily) into a temp directory of .rego + data.json,
then evaluates each command's input document against ``data.sift.decision`` by
invoking the OPA binary in subprocess ("embedded") mode.

Subprocess mode is the MVP default: simple, no daemon, no port. If per-call
latency proves annoying (PRD Open Question #1), this is the seam to swap in a
persistent ``opa run --server`` client without touching callers.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from sift_mcp.config import get_config, resolve_case_dir
from sift_mcp.exceptions import PolicyEngineError
from sift_mcp.policy.compiler import compile_policy
from sift_mcp.policy.parser import build_input_doc

logger = logging.getLogger(__name__)

# Repo-bundled OPA binary, used if opa is not on PATH and not configured.
_REPO_OPA = Path(__file__).resolve().parents[5] / "tools" / "opa"

_DECISION_QUERY = "data.sift.decision"


def _resolve_opa(configured: str = "") -> str:
    """Locate the opa binary: configured path → PATH → repo tools/opa."""
    if configured and Path(configured).exists():
        return configured
    found = shutil.which("opa")
    if found:
        return found
    if _REPO_OPA.exists():
        return str(_REPO_OPA)
    raise PolicyEngineError(
        "opa binary not found. Set SIFT_OPA_PATH, put opa on PATH, "
        "or place it at tools/opa."
    )


def _default_security_yaml() -> str:
    """Default security.yaml path from the catalog directory."""
    from sift_mcp.catalog import _find_catalog_dir

    return str(_find_catalog_dir() / "security.yaml")


class OpaEvaluator:
    """Evaluate input documents against the compiled sift.decision policy."""

    def __init__(self, compiled_dir: str | Path, opa_path: str, timeout: int = 10):
        self.compiled_dir = str(compiled_dir)
        self.opa_path = opa_path
        self.timeout = timeout

    def evaluate(self, input_doc: dict) -> dict:
        """Return the structured decision {allowed, reasons, policies_evaluated}.

        Raises PolicyEngineError if OPA cannot be invoked or returns an error.
        """
        try:
            proc = subprocess.run(
                [
                    self.opa_path,
                    "eval",
                    "--data",
                    self.compiled_dir,
                    "--stdin-input",
                    "--format",
                    "raw",
                    _DECISION_QUERY,
                ],
                input=json.dumps(input_doc),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise PolicyEngineError(f"OPA invocation failed: {exc}") from exc

        if proc.returncode != 0:
            raise PolicyEngineError(
                f"OPA eval returned {proc.returncode}: {proc.stderr.strip()[:500]}"
            )
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise PolicyEngineError(
                f"OPA produced non-JSON output: {proc.stdout[:200]!r}"
            ) from exc


# --- Process-wide lazy singleton (compile once, evaluate many) ---

_evaluator: OpaEvaluator | None = None
_compiled_dir: Path | None = None


def get_evaluator() -> OpaEvaluator:
    """Build (once) and return the process evaluator, compiling security.yaml."""
    global _evaluator, _compiled_dir
    if _evaluator is not None:
        return _evaluator

    config = get_config()
    security_yaml = config.security_yaml or _default_security_yaml()
    opa_path = _resolve_opa(config.opa_path)

    _compiled_dir = Path(tempfile.mkdtemp(prefix="sift-policy-"))
    try:
        compile_policy(security_yaml, _compiled_dir)
    except Exception as exc:
        raise PolicyEngineError(
            f"Failed to compile {security_yaml}: {exc}"
        ) from exc

    _evaluator = OpaEvaluator(_compiled_dir, opa_path)
    logger.info(
        "Policy engine ready: compiled %s -> %s (opa=%s)",
        security_yaml,
        _compiled_dir,
        opa_path,
    )
    return _evaluator


def reset_evaluator() -> None:
    """Drop the cached evaluator so the next call recompiles (config reload/tests)."""
    global _evaluator, _compiled_dir
    _evaluator = None
    _compiled_dir = None


def evaluate_command(command: list[str], *, context_extra: dict | None = None) -> dict:
    """Build the input document for a command and evaluate it.

    Injects the runtime context the stateful output-path policy needs
    (case_dir, cwd), matching what security.py reads at decision time.
    """
    context = {
        "case_dir": resolve_case_dir() or "",
        "cwd": str(Path.cwd().resolve()),
    }
    if context_extra:
        context.update(context_extra)
    doc = build_input_doc(command, context=context)
    return get_evaluator().evaluate(doc)
