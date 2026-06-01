"""Build an in-memory evidence graph from Valhuntir case files."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import networkx as nx

import forensic_mcp.graph.schema as schema

logger = logging.getLogger(__name__)

SOURCE_FILES = ("findings.json", "timeline.json", "evidence.json", "iocs.json")


class EvidenceGraph:
    """Lazy, read-only NetworkX graph over a case directory."""

    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self._graph: nx.DiGraph | None = None
        self._built_at = 0.0
        self._last_stats: dict[str, Any] = {}

    @property
    def graph(self) -> nx.DiGraph:
        if self._is_stale():
            self.rebuild()
        if self._graph is None:
            self.rebuild()
        return self._graph

    @property
    def stats(self) -> dict[str, Any]:
        if self._is_stale():
            self.rebuild()
        return dict(self._last_stats)

    def rebuild(self) -> dict[str, Any]:
        start = time.perf_counter()
        graph, stats = build_graph(self.case_dir, return_stats=True)
        stats["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 2)
        self._graph = graph
        self._built_at = time.time()
        self._last_stats = stats
        return dict(stats)

    def _is_stale(self) -> bool:
        if self._graph is None:
            return True
        for name in SOURCE_FILES:
            path = self.case_dir / name
            if path.exists() and path.stat().st_mtime > self._built_at:
                return True
        audit_dir = self.case_dir / "audit"
        if audit_dir.exists():
            for path in audit_dir.glob("*.jsonl"):
                if path.stat().st_mtime > self._built_at:
                    return True
        return False


def build_graph(
    case_dir: Path, return_stats: bool = False
) -> nx.DiGraph | tuple[nx.DiGraph, dict[str, Any]]:
    """Build evidence graph from case directory files."""
    graph = nx.DiGraph()
    stats: dict[str, Any] = {"malformed_audit_lines": 0}

    evidence_by_path, evidence_by_hash = _load_evidence(graph, case_dir)
    audit_entries = _load_audit_entries(graph, case_dir, stats)

    _load_findings(graph, case_dir)
    _load_timeline(graph, case_dir)
    _load_iocs(graph, case_dir)
    _link_audit_to_evidence(graph, audit_entries, evidence_by_path, evidence_by_hash)
    _link_audit_outputs(graph, audit_entries)

    stats.update(_graph_stats(graph))
    if return_stats:
        return graph, stats
    return graph


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists() or not path.read_text().strip():
        return default
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        logger.warning("Skipping invalid JSON file %s: %s", path, e)
        return default


def _load_findings(graph: nx.DiGraph, case_dir: Path) -> None:
    for finding in _as_list(_load_json(case_dir / "findings.json", [])):
        if not isinstance(finding, dict) or not finding.get("id"):
            continue
        fid = str(finding["id"])
        graph.add_node(fid, type=schema.NODE_FINDING, **schema.finding_props(finding))
        for audit_id in finding.get("audit_ids", []) or []:
            if audit_id:
                graph.add_edge(fid, str(audit_id), relation=schema.REL_CITES)
        host = finding.get("host")
        if host:
            host_id = _host_id(str(host))
            graph.add_node(host_id, type=schema.NODE_HOST, hostname=str(host))
            graph.add_edge(fid, host_id, relation=schema.REL_OBSERVED_ON)
        account = finding.get("affected_account")
        if account:
            account_id = _account_id(str(account))
            graph.add_node(
                account_id, type=schema.NODE_ACCOUNT, account_name=str(account)
            )
            graph.add_edge(fid, account_id, relation=schema.REL_AFFECTS)
        for related in finding.get("related_findings", []) or []:
            if related:
                graph.add_edge(fid, str(related), relation=schema.REL_CORROBORATES)


def _load_timeline(graph: nx.DiGraph, case_dir: Path) -> None:
    for event in _as_list(_load_json(case_dir / "timeline.json", [])):
        if not isinstance(event, dict) or not event.get("id"):
            continue
        event_id = str(event["id"])
        graph.add_node(
            event_id, type=schema.NODE_TIMELINE_EVENT, **schema.timeline_props(event)
        )
        for fid in event.get("related_findings", []) or []:
            if fid:
                graph.add_edge(event_id, str(fid), relation=schema.REL_SUPPORTS)
        host = event.get("host") or _infer_host(event)
        if host:
            host_id = _host_id(str(host))
            graph.add_node(host_id, type=schema.NODE_HOST, hostname=str(host))
            graph.add_edge(event_id, host_id, relation=schema.REL_OBSERVED_ON)


def _load_iocs(graph: nx.DiGraph, case_dir: Path) -> None:
    for ioc in _as_list(_load_json(case_dir / "iocs.json", [])):
        if not isinstance(ioc, dict) or not ioc.get("id"):
            continue
        ioc_id = str(ioc["id"])
        graph.add_node(ioc_id, type=schema.NODE_IOC, **schema.ioc_props(ioc))
        for fid in ioc.get("source_findings", []) or []:
            if fid:
                graph.add_edge(ioc_id, str(fid), relation=schema.REL_EXTRACTED_FROM)
        for sighting in ioc.get("sightings", []) or []:
            if isinstance(sighting, dict) and sighting.get("host"):
                host_id = _host_id(str(sighting["host"]))
                graph.add_node(
                    host_id, type=schema.NODE_HOST, hostname=str(sighting["host"])
                )
                graph.add_edge(ioc_id, host_id, relation=schema.REL_OBSERVED_ON)


def _load_evidence(
    graph: nx.DiGraph, case_dir: Path
) -> tuple[dict[str, str], dict[str, str]]:
    raw = _load_json(case_dir / "evidence.json", {"files": []})
    records = raw.get("files", []) if isinstance(raw, dict) else raw
    evidence_by_path: dict[str, str] = {}
    evidence_by_hash: dict[str, str] = {}
    for idx, evidence in enumerate(_as_list(records)):
        if not isinstance(evidence, dict):
            continue
        ev_id = str(evidence.get("id") or evidence.get("evidence_id") or f"E-{idx + 1:03d}")
        graph.add_node(ev_id, type=schema.NODE_EVIDENCE, **schema.evidence_props(evidence))
        path = evidence.get("path")
        if path:
            evidence_by_path[_norm_path(str(path))] = ev_id
        sha256 = evidence.get("sha256")
        if sha256:
            evidence_by_hash[str(sha256).lower()] = ev_id
    return evidence_by_path, evidence_by_hash


def _load_audit_entries(
    graph: nx.DiGraph, case_dir: Path, stats: dict[str, Any]
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    audit_dir = case_dir / "audit"
    if not audit_dir.exists():
        return entries
    for path in sorted(audit_dir.glob("*.jsonl")):
        try:
            lines = path.read_text().splitlines()
        except OSError as e:
            logger.warning("Skipping unreadable audit file %s: %s", path, e)
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                stats["malformed_audit_lines"] += 1
                continue
            if not isinstance(entry, dict):
                continue
            audit_id = entry.get("audit_id") or entry.get("evidence_id")
            if not audit_id:
                continue
            entry["audit_id"] = str(audit_id)
            entries.append(entry)
            graph.add_node(
                str(audit_id), type=schema.NODE_TOOL_EXECUTION, **schema.audit_props(entry)
            )
    return entries


def _link_audit_to_evidence(
    graph: nx.DiGraph,
    audit_entries: list[dict[str, Any]],
    evidence_by_path: dict[str, str],
    evidence_by_hash: dict[str, str],
) -> None:
    for entry in audit_entries:
        audit_id = entry["audit_id"]
        input_files = entry.get("input_files", []) or []
        input_hashes = entry.get("input_sha256s", []) or []
        for idx, input_file in enumerate(input_files):
            ev_id = _match_evidence(str(input_file), evidence_by_path)
            if not ev_id and idx < len(input_hashes):
                ev_id = evidence_by_hash.get(str(input_hashes[idx]).lower(), "")
            if ev_id:
                graph.add_edge(audit_id, ev_id, relation=schema.REL_PRODUCED_BY)


def _link_audit_outputs(graph: nx.DiGraph, audit_entries: list[dict[str, Any]]) -> None:
    output_to_audit: dict[str, str] = {}
    for entry in audit_entries:
        for output in _outputs_from_entry(entry):
            output_to_audit[_norm_path(str(output))] = entry["audit_id"]
    for entry in audit_entries:
        for input_file in entry.get("input_files", []) or []:
            producer = output_to_audit.get(_norm_path(str(input_file)))
            if producer and producer != entry["audit_id"]:
                graph.add_edge(entry["audit_id"], producer, relation=schema.REL_OUTPUT_OF)


def _outputs_from_entry(entry: dict[str, Any]) -> list[str]:
    summary = entry.get("result_summary", {})
    if not isinstance(summary, dict):
        return []
    outputs: list[str] = []
    if summary.get("output_file"):
        outputs.append(str(summary["output_file"]))
    if isinstance(summary.get("output_files"), list):
        outputs.extend(str(p) for p in summary["output_files"] if p)
    return outputs


def _match_evidence(input_file: str, evidence_by_path: dict[str, str]) -> str:
    normalized = _norm_path(input_file)
    if normalized in evidence_by_path:
        return evidence_by_path[normalized]
    for ev_path, ev_id in evidence_by_path.items():
        if normalized == ev_path or normalized.startswith(ev_path.rstrip("/") + "/"):
            return ev_id
        if ev_path.startswith(normalized.rstrip("/") + "/"):
            return ev_id
    return ""


def _graph_stats(graph: nx.DiGraph) -> dict[str, Any]:
    node_types: dict[str, int] = {}
    edge_types: dict[str, int] = {}
    for _, data in graph.nodes(data=True):
        node_type = data.get("type", "unknown")
        node_types[node_type] = node_types.get(node_type, 0) + 1
    for _, _, data in graph.edges(data=True):
        relation = data.get("relation", "unknown")
        edge_types[relation] = edge_types.get(relation, 0) + 1
    return {
        "rebuilt": True,
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "node_types": node_types,
        "edge_types": edge_types,
    }


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _norm_path(path: str) -> str:
    try:
        return str(Path(path).expanduser().resolve())
    except OSError:
        return str(Path(path).expanduser())


def _host_id(hostname: str) -> str:
    return f"host:{hostname.lower()}"


def _account_id(account: str) -> str:
    return f"acct:{account.lower()}"


def _infer_host(event: dict[str, Any]) -> str:
    for key in ("source", "description"):
        value = str(event.get(key, ""))
        if "host=" in value.lower():
            return value.split("host=", 1)[1].split()[0].strip(",;)")
    return ""
