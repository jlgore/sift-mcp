"""SIFT install manifest: the full set of forensic commands SIFT ships.

Generated offline by ``tools/sift_manifest.py`` from the teamdfir/sift-saltstack
salt states (ground-truthed with ``dpkg -L``). The catalog (``catalog.py``) is
the curated, FK-enriched subset; this manifest is the broader runnable surface
that ``run_command`` can reach. Discovery merges the two so an agent can see
both enriched tools and the long tail.

Schema per entry (see tools/sift_manifest.py):
    command, package, install_source, source_category,
    analysis_scope, binaries[], inferred, desktop_only
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_MANIFEST_PATH: Path | None = None
_manifest_cache: list[dict] | None = None


def _find_manifest_path() -> Path | None:
    """Locate sift_manifest.json (env override, else packaged data dir)."""
    global _MANIFEST_PATH
    if _MANIFEST_PATH is not None:
        return _MANIFEST_PATH

    env = os.environ.get("SIFT_MANIFEST_PATH")
    if env and Path(env).is_file():
        _MANIFEST_PATH = Path(env)
        return _MANIFEST_PATH

    # Relative to this file: src/sift_mcp/manifest.py → ../../data/manifest/
    packaged = Path(__file__).resolve().parent.parent.parent / "data" / "manifest" / "sift_manifest.json"
    if packaged.is_file():
        _MANIFEST_PATH = packaged
        return packaged

    return None


def load_manifest() -> list[dict]:
    """Load the SIFT manifest; returns [] (with a warning) if unavailable."""
    global _manifest_cache
    if _manifest_cache is not None:
        return _manifest_cache

    path = _find_manifest_path()
    if path is None:
        logger.warning("SIFT manifest not found; uncataloged tool discovery disabled.")
        _manifest_cache = []
        return _manifest_cache
    try:
        _manifest_cache = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        logger.warning("Failed to read SIFT manifest %s: %s", path, e)
        _manifest_cache = []
    return _manifest_cache


def clear_manifest_cache() -> None:
    """Reset the cache (used by tests)."""
    global _manifest_cache, _MANIFEST_PATH
    _manifest_cache = None
    _MANIFEST_PATH = None
