"""Deterministic evidence graph query functions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import networkx as nx

import forensic_mcp.graph.schema as schema
from forensic_mcp.graph.builder import EvidenceGraph


def evidence_chain(evidence_graph: EvidenceGraph, finding_id: str) -> dict[str, Any]:
    graph = evidence_graph.graph
    if finding_id not in graph:
        return {"error": f"Finding not found: {finding_id}", "chain_complete": False}
    finding = graph.nodes[finding_id]
    chain: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    hop = 1
    for _, audit_id, data in graph.out_edges(finding_id, data=True):
        if data.get("relation") != schema.REL_CITES:
            continue
        if (
            audit_id not in graph
            or graph.nodes[audit_id].get("type") != schema.NODE_TOOL_EXECUTION
        ):
            gaps.append(
                {
                    "from": finding_id,
                    "missing": audit_id,
                    "reason": "audit_id not found",
                }
            )
            continue
        chain.append(_hop(graph, hop, finding_id, audit_id, schema.REL_CITES))
        hop += 1
        evidence_edges = [
            (audit_id, ev_id, edata)
            for _, ev_id, edata in graph.out_edges(audit_id, data=True)
            if edata.get("relation") == schema.REL_PRODUCED_BY
        ]
        if not evidence_edges:
            gaps.append(
                {
                    "from": audit_id,
                    "reason": "audit entry has no linked registered evidence",
                }
            )
        for src, dst, edata in evidence_edges:
            chain.append(_hop(graph, hop, src, dst, edata.get("relation", "")))
            hop += 1
    return {
        "finding": _public_node(finding),
        "chain": chain,
        "chain_length": len(chain),
        "chain_complete": not gaps,
        "gaps": gaps,
    }


def cross_reference(
    evidence_graph: EvidenceGraph, entity: str, entity_type: str = ""
) -> dict[str, Any]:
    graph = evidence_graph.graph
    needle = entity.lower()
    matches: list[dict[str, Any]] = []
    hosts: set[str] = set()
    timestamps: list[str] = []
    for node_id, data in graph.nodes(data=True):
        node_type = data.get("type", "")
        if entity_type and node_type != entity_type:
            continue
        haystack = _search_text(node_id, data)
        if needle not in haystack.lower():
            continue
        matches.append(
            {
                "node_id": node_id,
                "node_type": node_type,
                "relation_path": _short_relation_path(graph, node_id),
                "context": _context(data),
            }
        )
        host = _host_for_node(graph, node_id, data)
        if host:
            hosts.add(host)
        ts = _timestamp(data)
        if ts:
            timestamps.append(ts)
    return {
        "entity": entity,
        "matches": matches[:50],
        "total_matches": len(matches),
        "hosts_seen_on": sorted(hosts),
        "first_seen": min(timestamps) if timestamps else None,
        "last_seen": max(timestamps) if timestamps else None,
    }


def temporal_neighbors(
    evidence_graph: EvidenceGraph,
    timestamp: str,
    window_seconds: int = 300,
    host: str = "",
) -> dict[str, Any]:
    graph = evidence_graph.graph
    anchor = _parse_ts(timestamp)
    if anchor is None:
        return {"error": f"Invalid timestamp: {timestamp}", "neighbors": []}
    host_filter = host.lower() if host else ""
    neighbors: list[dict[str, Any]] = []
    hosts: set[str] = set()
    temporal_types = (
        schema.NODE_FINDING,
        schema.NODE_TIMELINE_EVENT,
        schema.NODE_TOOL_EXECUTION,
    )
    for node_id, data in graph.nodes(data=True):
        if data.get("type") not in temporal_types:
            continue
        ts_text = _timestamp(data)
        ts = _parse_ts(ts_text)
        if ts is None:
            continue
        delta = int((ts - anchor).total_seconds())
        if abs(delta) > window_seconds:
            continue
        node_host = _host_for_node(graph, node_id, data)
        if host_filter and node_host.lower() != host_filter:
            continue
        if node_host:
            hosts.add(node_host)
        item = {
            "id": node_id,
            "type": data.get("type"),
            "timestamp": ts_text,
            "delta_seconds": delta,
            "host": node_host,
        }
        if data.get("type") == schema.NODE_FINDING:
            item["title"] = data.get("title", "")
        elif data.get("type") == schema.NODE_TIMELINE_EVENT:
            item["description"] = data.get("description", "")
        else:
            item["tool"] = data.get("tool", "")
            item["command"] = data.get("command", "")
        neighbors.append(item)
    neighbors.sort(key=lambda item: (item["delta_seconds"], item["id"]))
    return {
        "anchor": timestamp,
        "window_seconds": window_seconds,
        "host_filter": host or None,
        "neighbors": neighbors,
        "cross_host_activity": len(hosts) > 1,
        "hosts_active_in_window": sorted(hosts),
    }


def corroboration_map(
    evidence_graph: EvidenceGraph, finding_id: str = ""
) -> dict[str, Any]:
    graph = evidence_graph.graph
    if finding_id:
        if finding_id not in graph:
            return {"error": f"Finding not found: {finding_id}"}
        return _corroboration_for_finding(graph, finding_id)
    findings = [
        node_id
        for node_id, data in graph.nodes(data=True)
        if data.get("type") == schema.NODE_FINDING
    ]
    results = [_corroboration_for_finding(graph, fid) for fid in findings]
    summary = {"STRONG": 0, "PARTIAL": 0, "WEAK": 0}
    for result in results:
        summary[result["corroboration"]] += 1
    weakest = [
        {"id": r["finding_id"], "reason": r["reason"]}
        for r in results
        if r["corroboration"] == "WEAK"
    ]
    return {
        "total_findings": len(findings),
        "corroboration_summary": summary,
        "weakest_findings": weakest,
    }


def host_summary(evidence_graph: EvidenceGraph, hostname: str = "") -> dict[str, Any]:
    graph = evidence_graph.graph
    if hostname:
        return _single_host_summary(graph, hostname)
    hosts = sorted(
        data.get("hostname", node_id.removeprefix("host:"))
        for node_id, data in graph.nodes(data=True)
        if data.get("type") == schema.NODE_HOST
    )
    return {
        "hosts": [_single_host_summary(graph, h) for h in hosts],
        "total_hosts": len(hosts),
    }


def rebuild_evidence_graph(evidence_graph: EvidenceGraph) -> dict[str, Any]:
    return evidence_graph.rebuild()


def _corroboration_for_finding(graph: nx.DiGraph, finding_id: str) -> dict[str, Any]:
    audit_ids = [
        dst
        for _, dst, data in graph.out_edges(finding_id, data=True)
        if data.get("relation") == schema.REL_CITES
    ]
    tools: set[str] = set()
    evidence_files: set[str] = set()
    for audit_id in audit_ids:
        node = graph.nodes.get(audit_id, {})
        if node.get("tool"):
            tools.add(str(node["tool"]))
        for _, ev_id, data in graph.out_edges(audit_id, data=True):
            if data.get("relation") == schema.REL_PRODUCED_BY:
                evidence_files.add(ev_id)
    if len(evidence_files) >= 2 and len(tools) >= 2:
        level = "STRONG"
        reason = "Multiple tools and registered evidence files support this finding."
    elif evidence_files or len(audit_ids) >= 2:
        level = "PARTIAL"
        reason = "Some provenance exists, but corroboration is limited."
    else:
        level = "WEAK"
        reason = "No linked registered evidence or only uncorroborated audit support."
    return {
        "finding_id": finding_id,
        "sources": {
            "tool_executions": len(audit_ids),
            "unique_evidence_files": len(evidence_files),
            "unique_tools": sorted(tools),
        },
        "corroboration": level,
        "reason": reason,
        "suggested_checks": _suggested_checks(graph.nodes[finding_id]),
    }


def _single_host_summary(graph: nx.DiGraph, hostname: str) -> dict[str, Any]:
    host_id = f"host:{hostname.lower()}"
    if host_id not in graph:
        return {"host": hostname, "error": "host not found"}
    findings: set[str] = set()
    events: set[str] = set()
    iocs: set[str] = set()
    evidence: set[str] = set()
    accounts: set[str] = set()
    techniques: set[str] = set()
    timestamps: list[str] = []
    for src, _, _data in graph.in_edges(host_id, data=True):
        node = graph.nodes[src]
        node_type = node.get("type")
        if node_type == schema.NODE_FINDING:
            findings.add(src)
            techniques.update(node.get("mitre_ids", []) or [])
            ts = _timestamp(node)
            if ts:
                timestamps.append(ts)
            for _, acct_id, edata in graph.out_edges(src, data=True):
                if edata.get("relation") == schema.REL_AFFECTS:
                    accounts.add(graph.nodes[acct_id].get("account_name", acct_id))
            for _, audit_id, edata in graph.out_edges(src, data=True):
                if edata.get("relation") == schema.REL_CITES:
                    for _, ev_id, evdata in graph.out_edges(audit_id, data=True):
                        if evdata.get("relation") == schema.REL_PRODUCED_BY:
                            evidence.add(ev_id)
        elif node_type == schema.NODE_TIMELINE_EVENT:
            events.add(src)
            ts = _timestamp(node)
            if ts:
                timestamps.append(ts)
        elif node_type == schema.NODE_IOC:
            iocs.add(src)
            techniques.update(node.get("mitre_techniques", []) or [])
    return {
        "host": graph.nodes[host_id].get("hostname", hostname),
        "findings_count": len(findings),
        "timeline_events_count": len(events),
        "iocs_count": len(iocs),
        "evidence_files": len(evidence),
        "time_range": {
            "first_activity": min(timestamps) if timestamps else None,
            "last_activity": max(timestamps) if timestamps else None,
        },
        "findings": sorted(findings),
        "attack_techniques": sorted(techniques),
        "accounts_involved": sorted(accounts),
    }


def _hop(
    graph: nx.DiGraph, hop: int, src: str, dst: str, relation: str
) -> dict[str, Any]:
    return {
        "hop": hop,
        "from": src,
        "relation": relation,
        "to": dst,
        "node_type": graph.nodes[dst].get("type", "unknown")
        if dst in graph
        else "missing",
        "detail": _public_node(graph.nodes[dst]) if dst in graph else {},
    }


def _public_node(data: dict[str, Any]) -> dict[str, Any]:
    excluded = {"result_summary", "observation", "interpretation"}
    return {k: v for k, v in data.items() if k not in excluded and k != "type"}


def _search_text(node_id: str, data: dict[str, Any]) -> str:
    values = [node_id]
    for value in data.values():
        if isinstance(value, (str, int, float)):
            values.append(str(value))
        elif isinstance(value, list):
            values.extend(str(v) for v in value[:20])
    return " ".join(values)


def _short_relation_path(graph: nx.DiGraph, node_id: str) -> str:
    incoming = list(graph.in_edges(node_id, data=True))[:1]
    if incoming:
        src, _, data = incoming[0]
        return f"{src} -> {data.get('relation')} -> {node_id}"
    outgoing = list(graph.out_edges(node_id, data=True))[:1]
    if outgoing:
        _, dst, data = outgoing[0]
        return f"{node_id} -> {data.get('relation')} -> {dst}"
    return node_id


def _context(data: dict[str, Any]) -> str:
    for key in ("title", "description", "value", "path", "command", "tool"):
        if data.get(key):
            return str(data[key])[:300]
    return ""


def _timestamp(data: dict[str, Any]) -> str:
    return str(
        data.get("event_timestamp") or data.get("timestamp") or data.get("ts") or ""
    )


def _host_for_node(graph: nx.DiGraph, node_id: str, data: dict[str, Any]) -> str:
    if data.get("host"):
        return str(data["host"])
    if data.get("type") == schema.NODE_HOST:
        return str(data.get("hostname", ""))
    for _, dst, edata in graph.out_edges(node_id, data=True):
        if edata.get("relation") == schema.REL_OBSERVED_ON:
            return str(graph.nodes[dst].get("hostname", ""))
    return ""


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _suggested_checks(finding: dict[str, Any]) -> list[str]:
    finding_type = str(finding.get("finding_type", ""))
    if finding_type:
        try:
            from forensic_knowledge import loader

            checks = loader.get_corroboration(finding_type)
        except Exception:
            checks = []
        suggestions = []
        for check in checks or []:
            if isinstance(check, dict):
                check_text = check.get("check", "")
                reason = check.get("reason", "")
                if check_text:
                    suggestions.append(
                        f"{check_text} — {reason}" if reason else check_text
                    )
            elif check:
                suggestions.append(str(check))
        if suggestions:
            return suggestions[:5]

    title = str(finding.get("title", "")).lower()
    observation = str(finding.get("observation", "")).lower()
    text = f"{title} {observation}"
    checks = []
    if "amcache" in text:
        checks.extend(
            [
                "Run PECmd against Prefetch files for execution corroboration.",
                "Check UserAssist for user-driven execution evidence.",
                "Search process creation events for matching executable names.",
            ]
        )
    if not checks:
        checks.append("Seek an independent artifact source before raising confidence.")
    return checks
