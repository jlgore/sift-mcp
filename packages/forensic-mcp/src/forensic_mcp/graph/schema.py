"""Schema helpers for evidence graph nodes and edges."""

from __future__ import annotations

from typing import Any

NODE_FINDING = "finding"
NODE_TIMELINE_EVENT = "timeline_event"
NODE_EVIDENCE = "evidence"
NODE_TOOL_EXECUTION = "tool_execution"
NODE_IOC = "ioc"
NODE_HOST = "host"
NODE_ACCOUNT = "account"

REL_CITES = "cites"
REL_PRODUCED_BY = "produced_by"
REL_EXTRACTED_FROM = "extracted_from"
REL_OBSERVED_ON = "observed_on"
REL_AFFECTS = "affects"
REL_SUPPORTS = "supports"
REL_CORROBORATES = "corroborates"
REL_OUTPUT_OF = "output_of"


def compact_props(data: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """Return non-empty values for selected keys."""
    return {k: data.get(k) for k in keys if data.get(k) not in (None, "", [])}


def finding_props(finding: dict[str, Any]) -> dict[str, Any]:
    props = compact_props(
        finding,
        (
            "id",
            "title",
            "status",
            "confidence",
            "type",
            "host",
            "affected_account",
            "event_timestamp",
            "observation",
            "interpretation",
            "mitre_ids",
        ),
    )
    if "type" in props:
        props["finding_type"] = props.pop("type")
    return props


def timeline_props(event: dict[str, Any]) -> dict[str, Any]:
    return compact_props(
        event,
        ("id", "timestamp", "description", "event_type", "source", "status", "host"),
    )


def evidence_props(evidence: dict[str, Any]) -> dict[str, Any]:
    return compact_props(
        evidence,
        (
            "id",
            "path",
            "sha256",
            "description",
            "registered_at",
            "registered_by",
            "size",
        ),
    )


def ioc_props(ioc: dict[str, Any]) -> dict[str, Any]:
    props = compact_props(
        ioc,
        (
            "id",
            "value",
            "type",
            "category",
            "status",
            "confidence",
            "source_findings",
            "sightings",
            "mitre_techniques",
        ),
    )
    if "type" in props:
        props["ioc_type"] = props.pop("type")
    return props


def audit_props(entry: dict[str, Any]) -> dict[str, Any]:
    return compact_props(
        entry,
        (
            "audit_id",
            "ts",
            "mcp",
            "tool",
            "source",
            "elapsed_ms",
            "input_files",
            "input_sha256s",
            "input_detection_method",
            "source_evidence",
        ),
    ) | {
        "command": _command_from_entry(entry),
        "result_summary": entry.get("result_summary", {}),
    }


def _command_from_entry(entry: dict[str, Any]) -> str:
    params = entry.get("params", {})
    if isinstance(params, dict):
        for key in ("command", "cmd"):
            if params.get(key):
                return str(params[key])
    return ""
