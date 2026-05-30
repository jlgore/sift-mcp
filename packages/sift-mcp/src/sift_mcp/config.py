"""Configuration for sift-mcp."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from sift_common import resolve_case_dir  # noqa: F401


@dataclass
class SiftConfig:
    """Runtime configuration loaded from environment."""

    # Tool binary search paths
    tool_paths: list[str] = field(
        default_factory=lambda: [
            "/usr/local/bin",
            "/usr/bin",
            "/opt/zimmerman",
            "/opt/volatility3",
        ]
    )

    # Default execution timeout (seconds)
    default_timeout: int = 600

    # Max bytes captured from subprocess (safety limit for runaway processes)
    max_output_bytes: int = 52_428_800  # 50MB

    # Max bytes of tool output returned in MCP response (~2,500 tokens)
    response_byte_budget: int = 10_240  # 10KB

    # Hayabusa install location
    hayabusa_dir: str = "/opt/hayabusa"

    # Case directory (from env)
    case_dir: str = ""

    # SMB share mount point for wintools extraction files
    share_root: str = ""

    # --- Layer 1: OPA policy engine ---
    # Off by default so the OPA gate is a no-op until explicitly enabled.
    # security.py enforcement always runs regardless (belt-and-suspenders).
    policy_engine_enabled: bool = False
    # Path to the opa binary ("" → resolve from PATH, then repo tools/opa).
    opa_path: str = ""
    # Path to security.yaml to compile ("" → catalog default).
    security_yaml: str = ""

    # --- Layer 2: bubblewrap sandbox ---
    # Off by default; when on, every tool runs inside a bwrap namespace with
    # evidence read-only and network isolated.
    sandbox_enabled: bool = False
    sandbox_profile: str = "default"
    # Path to the bwrap binary ("" → "bwrap" on PATH).
    bwrap_path: str = ""

    @classmethod
    def from_env(cls) -> SiftConfig:
        cfg = cls()
        cfg.case_dir = resolve_case_dir()
        cfg.share_root = os.environ.get("VHIR_SHARE_ROOT", "")

        cfg.policy_engine_enabled = os.environ.get(
            "SIFT_POLICY_ENGINE", ""
        ).lower() in ("1", "true", "yes", "on")
        cfg.opa_path = os.environ.get("SIFT_OPA_PATH", "")
        cfg.security_yaml = os.environ.get("SIFT_SECURITY_YAML", "")

        cfg.sandbox_enabled = os.environ.get("SIFT_SANDBOX", "").lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        if os.environ.get("SIFT_SANDBOX_PROFILE"):
            cfg.sandbox_profile = os.environ["SIFT_SANDBOX_PROFILE"]
        cfg.bwrap_path = os.environ.get("SIFT_BWRAP_PATH", "")

        extra_paths = os.environ.get("SIFT_TOOL_PATHS", "")
        if extra_paths:
            cfg.tool_paths = extra_paths.split(":") + cfg.tool_paths

        timeout = os.environ.get("SIFT_TIMEOUT")
        if timeout and timeout.isdigit():
            cfg.default_timeout = int(timeout)

        hayabusa = os.environ.get("SIFT_HAYABUSA_DIR")
        if hayabusa:
            cfg.hayabusa_dir = hayabusa

        if os.environ.get("SIFT_RESPONSE_BUDGET"):
            try:
                cfg.response_byte_budget = int(os.environ["SIFT_RESPONSE_BUDGET"])
            except ValueError:
                pass

        if os.environ.get("SIFT_MAX_OUTPUT"):
            try:
                cfg.max_output_bytes = int(os.environ["SIFT_MAX_OUTPUT"])
            except ValueError:
                pass

        return cfg


def get_config() -> SiftConfig:
    return SiftConfig.from_env()
