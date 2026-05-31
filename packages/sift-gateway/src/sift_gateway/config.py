"""YAML config loading with environment variable interpolation."""

import logging
import os
import re
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _interpolate_env(value: str) -> str:
    """Replace ${VAR} patterns with environment variable values.

    If a referenced variable is not set, the placeholder is replaced with
    an empty string to prevent literal '${VAR}' from leaking into configs.
    """

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, "")

    return _ENV_VAR_PATTERN.sub(_replace, value)


def _walk_and_interpolate(obj):
    """Recursively walk a parsed YAML structure and interpolate strings."""
    if isinstance(obj, str):
        return _interpolate_env(obj)
    if isinstance(obj, dict):
        return {k: _walk_and_interpolate(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_and_interpolate(item) for item in obj]
    return obj


def load_config(path: str) -> dict:
    """Load a YAML config file with env var interpolation.

    Args:
        path: Path to the YAML config file.

    Returns:
        Parsed and interpolated config dict.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError: If the file is not valid YAML.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.error("Invalid YAML in config file %s: %s", path, e)
        raise
    except OSError as e:
        logger.error("Cannot read config file %s: %s", path, e)
        raise

    if raw is None:
        return {}

    if not isinstance(raw, dict):
        raise ValueError(
            f"Config file must contain a YAML mapping, got {type(raw).__name__}: {path}"
        )

    config = _walk_and_interpolate(raw)
    apply_security_layers(config)
    return config


def _as_flag(value) -> str:
    """Normalize a YAML truthy value to the "1"/"0" form SiftConfig reads."""
    if isinstance(value, bool):
        return "1" if value else "0"
    return "1" if str(value).strip().lower() in ("1", "true", "yes", "on") else "0"


# Top-level gateway.yaml security sections (PRD §7) → the SIFT_* env vars that
# sift-mcp's SiftConfig.from_env() reads. Only fields with a real env-var
# counterpart are translated; documentation-only PRD fields (opa_mode,
# compiled_dir, log_decisions, timeout, …) are ignored here. The value of each
# entry is (env_var_name, coercion_fn).
_POLICY_ENGINE_ENV = {
    "enabled": ("SIFT_POLICY_ENGINE", _as_flag),
    "opa_path": ("SIFT_OPA_PATH", str),
    "security_yaml": ("SIFT_SECURITY_YAML", str),
}
_SANDBOX_ENV = {
    "enabled": ("SIFT_SANDBOX", _as_flag),
    "profile": ("SIFT_SANDBOX_PROFILE", str),
    "bwrap_path": ("SIFT_BWRAP_PATH", str),
}


def _build_security_overlay(config: dict) -> dict:
    """Project the ``policy_engine`` / ``sandbox`` sections into an env overlay."""
    overlay: dict[str, str] = {}
    for section_key, mapping in (
        ("policy_engine", _POLICY_ENGINE_ENV),
        ("sandbox", _SANDBOX_ENV),
    ):
        section = config.get(section_key) or {}
        if not isinstance(section, dict):
            continue
        for field_name, (env_var, coerce) in mapping.items():
            if field_name not in section:
                continue
            value = section[field_name]
            # Skip empty values (e.g. an unset ${VAR} that interpolated to "")
            # so SiftConfig falls back to its own resolution.
            if value is None or value == "":
                continue
            overlay[env_var] = coerce(value)
    return overlay


def apply_security_layers(config: dict) -> dict:
    """Translate top-level security sections onto the sift-mcp backend env.

    sift-mcp gates its two enforcement layers — Layer 1 (OPA policy engine)
    and Layer 2 (bubblewrap sandbox) — on ``SIFT_*`` environment variables
    read fresh on every ``run_command``. The gateway exposes these as
    first-class ``policy_engine:`` / ``sandbox:`` config sections (PRD §7) and
    injects the corresponding env vars into the sift-mcp backend's ``env`` dict
    here, so enforcement is enabled by editing ``gateway.yaml`` rather than by
    exporting env vars before launching the gateway.

    The overlay only targets stdio backends that run ``sift_mcp`` (matched by
    module in ``args``). Values already present in a backend's explicit ``env``
    win, so a per-backend override is always possible. Mutates ``config`` in
    place and returns it.
    """
    overlay = _build_security_overlay(config)
    if not overlay:
        return config

    for name, backend in (config.get("backends") or {}).items():
        if not isinstance(backend, dict):
            continue
        if "sift_mcp" not in (backend.get("args") or []):
            continue
        env = backend.setdefault("env", {})
        if not isinstance(env, dict):
            continue
        for env_var, value in overlay.items():
            env.setdefault(env_var, value)  # explicit backend env wins
        logger.info(
            "Applied security layers to backend %s: %s",
            name,
            ", ".join(sorted(overlay)),
        )
    return config
