"""Pydantic schema for security.yaml -> validated policy -> OPA data.json.

The existing ``security.yaml`` defines five fields (dangerous_flags,
tool_allowed_flags, tool_blocked_flags, output_flags, denied_binaries). The
remaining enforcement values live *hardcoded* in ``security.py`` today
(_BLOCKED_DIRECTORIES, _OUTPUT_BLOCKED_DIRECTORIES, _DANGEROUS_PATTERNS, the
awk tool set, rm-protected dirs). This schema lifts those into defaults so the
compiled OPA data carries the complete policy while keeping security.yaml
backward compatible — practitioners can override any of them in YAML, but a
stock security.yaml still produces full-parity data.

Default directory values are resolved at validation time (``~`` expanded,
env-driven case roots applied) so data.json contains absolute paths the
parser's resolved input paths can be compared against with simple prefix
checks in Rego.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

# --- Defaults migrated from sift_mcp.security (single source kept in sync via
# --- the parity harness). Expressed as module constants so they're greppable.

_DEFAULT_SHELL_METACHARACTERS = [";", "&&", "||", "`", "$(", "${"]
_DEFAULT_AWK_PROGRAM_TOOLS = ["awk", "gawk", "mawk", "nawk"]

# awk program-text danger regex, RE2-safe form of security.py:_AWK_DANGEROUS_RE.
# Python's re tolerates the redundant \" escapes; Go's RE2 (used by OPA) does
# not, so the backslashes before double-quotes are dropped (a literal " needs
# no escaping). The matched constructs are identical: system(), getline, and
# pipe/redirect-into-string operators.
_DEFAULT_AWK_DANGER_REGEX = r'system\s*\(|getline|".*\||\|.*"|>\s*"|>>\s*"'

# Base blocked input dirs (security.py:_BLOCKED_DIRECTORIES, minus the
# home-relative ~/.vhir which is appended at validation time).
_DEFAULT_BLOCKED_INPUT_DIRS_BASE = ["/etc", "/proc", "/sys", "/dev", "/boot"]

# Extra dirs blocked for output only (security.py:_OUTPUT_BLOCKED_DIRECTORIES
# superset adds these on top of the input dirs).
_DEFAULT_OUTPUT_ONLY_DIRS = ["/usr", "/bin", "/sbin", "/lib", "/var", "/home"]


def _expand(path: str) -> str:
    """Expand ~ and make absolute so Rego prefix checks line up with resolved
    input paths."""
    return str(Path(os.path.expanduser(path)).resolve()) if path else path


class SecurityPolicy(BaseModel):
    """Validated representation of security.yaml, ready to emit as OPA data."""

    model_config = ConfigDict(extra="forbid")

    # --- Existing security.yaml fields ---
    dangerous_flags: list[str] = Field(default_factory=list)
    tool_allowed_flags: dict[str, list[str]] = Field(default_factory=dict)
    tool_blocked_flags: dict[str, list[str]] = Field(default_factory=dict)
    output_flags: list[str] = Field(default_factory=list)
    denied_binaries: list[str] = Field(default_factory=list)

    # --- Fields migrated from security.py (overridable in YAML) ---
    shell_metacharacters: list[str] = Field(
        default_factory=lambda: list(_DEFAULT_SHELL_METACHARACTERS)
    )
    awk_program_tools: list[str] = Field(
        default_factory=lambda: list(_DEFAULT_AWK_PROGRAM_TOOLS)
    )
    awk_danger_regex: str = _DEFAULT_AWK_DANGER_REGEX
    blocked_input_dirs: list[str] | None = None
    blocked_input_exceptions: list[str] | None = None
    blocked_output_dirs: list[str] | None = None
    protected_rm_dirs: list[str] | None = None

    def to_data(self) -> dict:
        """Produce the OPA data.json document (resolved, absolute, lowercased
        where security.py lowercases).

        denied_binaries are lowercased because is_denied() compares
        ``binary.lower()``. Flags are kept as authored; the Rego rules call
        ``lower()`` at evaluation time, matching sanitize_extra_args().
        """
        home_vhir = _expand("~/.vhir")
        cases_dir = _expand(os.environ.get("VHIR_CASES_DIR", "~/cases"))

        blocked_input = self.blocked_input_dirs or (
            _DEFAULT_BLOCKED_INPUT_DIRS_BASE + [home_vhir]
        )
        blocked_input_exceptions = self.blocked_input_exceptions or [
            _expand("~/.vhir/cases"),
            _expand("~/.vhir/hayabusa-output"),
        ]
        blocked_output = self.blocked_output_dirs or (
            list(blocked_input) + list(_DEFAULT_OUTPUT_ONLY_DIRS)
        )
        protected_rm = self.protected_rm_dirs or [cases_dir, "/cases", "/evidence"]

        return {
            "denied_binaries": sorted({b.lower() for b in self.denied_binaries}),
            "dangerous_flags": list(self.dangerous_flags),
            "tool_allowed_flags": {
                k: list(v) for k, v in self.tool_allowed_flags.items()
            },
            "tool_blocked_flags": {
                k: list(v) for k, v in self.tool_blocked_flags.items()
            },
            "output_flags": list(self.output_flags),
            "shell_metacharacters": list(self.shell_metacharacters),
            "awk_program_tools": list(self.awk_program_tools),
            "blocked_input_dirs": list(blocked_input),
            "blocked_input_exceptions": list(blocked_input_exceptions),
            "blocked_output_dirs": list(blocked_output),
            "protected_rm_dirs": list(protected_rm),
        }
