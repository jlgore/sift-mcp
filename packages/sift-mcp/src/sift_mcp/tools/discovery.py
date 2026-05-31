"""Tool discovery: list tools, suggest tools, check availability."""

from __future__ import annotations

import itertools
import logging

logger = logging.getLogger(__name__)
from forensic_knowledge import loader

from sift_mcp.catalog import get_tool_def, list_tools_in_catalog
from sift_mcp.environment import find_binary
from sift_mcp.manifest import load_manifest
from sift_mcp.response import DISCIPLINE_REMINDERS

# Alias mapping — common artifact names to FK artifact YAML names
ARTIFACT_ALIASES: dict[str, list[str]] = {
    "evtx": [
        "event_logs_security",
        "event_logs_system",
        "event_logs_sysmon",
        "event_logs_powershell",
    ],
    "evt": ["event_logs_security", "event_logs_system"],
    "event_log": ["event_logs_security", "event_logs_system", "event_logs_sysmon"],
    "event_logs": ["event_logs_security", "event_logs_system", "event_logs_sysmon"],
    "registry": ["registry_run_keys", "registry_services", "shellbags", "shimcache"],
    "mft": ["mft"],
    "prefetch": ["prefetch"],
    "usn": ["usn_journal"],
    "userassist": ["userassist"],
    "amcache": ["amcache"],
}

_suggest_counter = itertools.count(1)

# Layer 7b: SIFT limitations where wintools-mcp produces better results
_SIFT_LIMITATIONS: dict[str, str] = {
    "srum": (
        "SRUM parsing on SIFT uses Plaso (limited dirty-database handling). "
        "For reliable SRUM analysis, provision wintools-mcp with SrumECmd."
    ),
    "prefetch": (
        "Prefetch parsing on SIFT uses Plaso (misses execution counts, loaded DLLs). "
        "For complete prefetch analysis, provision wintools-mcp with PECmd."
    ),
    "registry": (
        "Registry parsing on SIFT has limited transaction log recovery. "
        "For dirty hives from KAPE live collection, provision wintools-mcp with RECmd."
    ),
    "digital_signatures": (
        "SIFT cannot verify Authenticode signatures. "
        "For signature verification, provision wintools-mcp with sigcheck."
    ),
}


def _wintools_available() -> bool:
    """Check if wintools-mcp is configured in gateway.yaml."""
    try:
        from pathlib import Path

        import yaml

        gw = yaml.safe_load((Path.home() / ".vhir" / "gateway.yaml").read_text()) or {}
        return "wintools-mcp" in gw.get("backends", {})
    except Exception:
        return False


def list_available_tools(
    category: str | None = None,
    include_uncataloged: bool = False,
    include_live_network: bool = False,
) -> list[dict]:
    """List forensic tools available on this SIFT workstation.

    By default returns the curated catalog: tools with FK enrichment (caveats,
    corroboration, field meanings) wired into run_command responses.

    With ``include_uncataloged=True`` it also returns the broader set of forensic
    commands SIFT installs (from the install manifest) — runnable via run_command
    but without FK enrichment (``enriched: false``). live_network tools (hydra,
    nikto, aircrack-ng…) are excluded unless ``include_live_network=True``,
    because the execution sandbox runs with the network unshared.

    Every entry carries: name, command, category, available, enriched,
    analysis_scope, and fk_tool (None when unenriched).
    """
    # scope lookup from the manifest, keyed by command (case-insensitive)
    scope_by_cmd = {m["command"].lower(): m["analysis_scope"] for m in load_manifest()}

    results: list[dict] = []
    catalog_cmds: set[str] = set()
    for t in list_tools_in_catalog(category=category):
        td = get_tool_def(t["name"])
        binary = td.binary if td else t["name"]
        catalog_cmds.add(binary.lower())
        path = find_binary(binary) if td else None
        entry = {
            **t,
            "command": binary,
            "available": path is not None,
            "enriched": True,
            "analysis_scope": scope_by_cmd.get(binary.lower(), "offline"),
            "fk_tool": (td.fk_tool_name or td.binary) if td else None,
        }
        if path:
            entry["binary_path"] = path
        results.append(entry)

    if not include_uncataloged:
        return results

    for m in load_manifest():
        cmd = m["command"]
        if cmd.lower() in catalog_cmds:
            continue  # already covered by the (enriched) catalog entry
        if category and category not in (m["source_category"], m["install_source"]):
            continue
        if m["analysis_scope"] == "live_network" and not include_live_network:
            continue
        results.append(
            {
                "name": cmd,
                "command": cmd,
                "category": "uncataloged",
                "package": m["package"],
                "install_source": m["install_source"],
                "available": find_binary(cmd) is not None,
                "enriched": False,
                "analysis_scope": m["analysis_scope"],
                "fk_tool": None,
            }
        )
    return results


def get_tool_help(tool_name: str) -> dict:
    """Get usage information for a specific tool."""
    td = get_tool_def(tool_name)
    if not td:
        return {"error": f"Tool '{tool_name}' not in catalog"}

    result = {
        "name": td.name,
        "binary": td.binary,
        "category": td.category,
        "description": td.description,
        "input_style": td.input_style,
        "input_flag": td.input_flag,
        "output_format": td.output_format,
        "timeout_seconds": td.timeout_seconds,
        "common_flags": td.common_flags,
        "available": find_binary(td.binary) is not None,
    }

    # Add FK knowledge
    try:
        fk = loader.get_tool(td.knowledge_name)
    except Exception as e:
        logger.debug("FK lookup failed for %s: %s", td.knowledge_name, e)
        fk = None
    if fk:
        result["caveats"] = fk.get("caveats", [])
        result["advisories"] = fk.get("advisories", [])
        result["artifacts_parsed"] = fk.get("artifacts_parsed", [])
        if fk.get("quick_start"):
            result["quick_start"] = fk["quick_start"]
        if fk.get("investigation_sequence"):
            result["investigation_sequence"] = fk["investigation_sequence"]
        if fk.get("field_meanings"):
            result["field_meanings"] = fk["field_meanings"]

    return result


def check_tools(tool_names: list[str] | None = None) -> dict:
    """Check availability of tools on the system."""
    if tool_names:
        results = {}
        for name in tool_names:
            td = get_tool_def(name)
            if td:
                path = find_binary(td.binary)
                results[name] = {"available": path is not None, "binary_path": path}
            else:
                results[name] = {
                    "available": False,
                    "note": "not in catalog — can execute but without FK enrichment",
                }
        return results

    # Check all
    tools = list_tools_in_catalog()
    results = {}
    for t in tools:
        td = get_tool_def(t["name"])
        if td:
            path = find_binary(td.binary)
            results[t["name"]] = {"available": path is not None, "binary_path": path}
    return results


def suggest_tools(artifact_type: str, question: str = "") -> dict:
    """Suggest tools based on artifact type, using FK knowledge.

    Returns an enriched envelope with suggestions, advisories, corroboration,
    cross-MCP checks, and discipline reminders.
    """
    # Resolve aliases
    artifact_names = ARTIFACT_ALIASES.get(artifact_type.lower(), [artifact_type])

    suggestions: list[dict] = []
    all_advisories: list[str] = []
    all_corroboration: dict[str, list[str]] = {}
    all_cross_mcp: list[dict] = []

    # Layer 7b: add SIFT limitation advisories when wintools unavailable
    if not _wintools_available():
        for art_name in artifact_names:
            if art_name in _SIFT_LIMITATIONS:
                all_advisories.append(_SIFT_LIMITATIONS[art_name])

    for art_name in artifact_names:
        try:
            artifact = loader.get_artifact(art_name)
        except Exception as e:
            logger.debug("FK artifact lookup failed for %s: %s", art_name, e)
            continue
        if not artifact:
            continue

        for tool_name in artifact.get("related_tools", []):
            # Avoid duplicates across aliases
            if any(s.get("tool") == tool_name for s in suggestions):
                continue
            td = get_tool_def(tool_name)
            try:
                fk = loader.get_tool(tool_name)
            except Exception as e:
                logger.debug("FK tool lookup failed for %s: %s", tool_name, e)
                fk = None
            entry = {
                "tool": tool_name,
                "artifact": art_name,
                "available": find_binary(td.binary) is not None if td else False,
                "description": fk.get("description", "") if fk else "",
                "what_it_reveals": artifact.get("proves", []),
                "what_it_does_not_reveal": artifact.get("does_not_prove", []),
            }
            suggestions.append(entry)

        # Advisories from does_not_prove
        for item in artifact.get("does_not_prove", []):
            advisory = f"This artifact does NOT prove: {item}"
            if advisory not in all_advisories:
                all_advisories.append(advisory)

        # Corroboration map
        for key, val in artifact.get("corroborate_with", {}).items():
            if key not in all_corroboration:
                all_corroboration[key] = []
            for ref in val:
                if ref not in all_corroboration[key]:
                    all_corroboration[key].append(ref)

        # Cross-MCP checks
        for check in artifact.get("cross_mcp_checks", []):
            if check not in all_cross_mcp:
                all_cross_mcp.append(check)

    if not suggestions:
        try:
            available = [a["name"] for a in loader.list_artifacts()]
        except Exception as e:
            logger.debug("FK list_artifacts failed: %s", e)
            available = []
        return {
            "suggestions": [],
            "info": f"No tools found for artifact type '{artifact_type}'",
            "available_artifacts": available,
        }

    call_num = next(_suggest_counter)
    return {
        "suggestions": suggestions,
        "advisories": all_advisories,
        "corroboration": all_corroboration,
        "cross_mcp_checks": all_cross_mcp,
        "discipline_reminder": DISCIPLINE_REMINDERS[
            call_num % len(DISCIPLINE_REMINDERS)
        ],
    }
