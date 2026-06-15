"""Tests for forensic-mcp evidence graph."""

import json

from forensic_mcp.graph import EvidenceGraph, build_graph, queries


def _write_json(path, data):
    path.write_text(json.dumps(data, indent=2))


def _case_dir(tmp_path):
    case_dir = tmp_path / "INC-2026-0001"
    case_dir.mkdir()
    (case_dir / "audit").mkdir()
    evidence_path = case_dir / "evidence" / "Amcache.hve"
    evidence_path.parent.mkdir()
    evidence_path.write_text("amcache data")

    _write_json(
        case_dir / "evidence.json",
        {
            "files": [
                {
                    "id": "E-tester-001",
                    "path": str(evidence_path),
                    "sha256": "a" * 64,
                    "description": "Amcache hive",
                    "registered_at": "2026-06-01T14:00:00Z",
                }
            ]
        },
    )
    _write_json(
        case_dir / "findings.json",
        [
            {
                "id": "F-tester-001",
                "title": "Mimikatz installation detected via Amcache",
                "status": "DRAFT",
                "confidence": "MEDIUM",
                "type": "finding",
                "audit_ids": ["sift-tester-20260601-001"],
                "host": "NFURY",
                "affected_account": "SHIELDBASE\\nromanoff",
                "event_timestamp": "2024-03-15T14:32:07Z",
                "mitre_ids": ["T1003.001"],
            }
        ],
    )
    _write_json(
        case_dir / "timeline.json",
        [
            {
                "id": "T-tester-001",
                "timestamp": "2024-03-15T14:33:00Z",
                "description": "cmd.exe spawned by wsmprovhost.exe",
                "event_type": "process",
                "source": "Security.evtx",
                "status": "DRAFT",
                "host": "NFURY",
                "related_findings": ["F-tester-001"],
            }
        ],
    )
    _write_json(
        case_dir / "iocs.json",
        [
            {
                "id": "IOC-tester-001",
                "value": "mimikatz.exe",
                "type": "file:name",
                "category": "host",
                "source_findings": ["F-tester-001"],
                "sightings": [{"host": "NFURY", "finding_id": "F-tester-001"}],
                "mitre_techniques": ["T1003.001"],
            }
        ],
    )
    (case_dir / "audit" / "sift-mcp.jsonl").write_text(
        json.dumps(
            {
                "ts": "2026-06-01T14:30:00Z",
                "mcp": "sift-mcp",
                "tool": "run_command",
                "audit_id": "sift-tester-20260601-001",
                "params": {"command": "AmcacheParser -f Amcache.hve --csv out"},
                "result_summary": {
                    "output_file": str(case_dir / "out" / "amcache.csv")
                },
                "input_files": [str(evidence_path)],
                "input_sha256s": ["a" * 64],
            }
        )
        + "\nnot-json\n"
    )
    return case_dir


def test_build_graph_from_case_files(tmp_path):
    case_dir = _case_dir(tmp_path)
    graph, stats = build_graph(case_dir, return_stats=True)

    assert graph.nodes["F-tester-001"]["type"] == "finding"
    assert graph.nodes["E-tester-001"]["type"] == "evidence"
    assert graph.has_edge("F-tester-001", "sift-tester-20260601-001")
    assert graph.has_edge("sift-tester-20260601-001", "E-tester-001")
    assert graph.has_edge("IOC-tester-001", "F-tester-001")
    assert stats["malformed_audit_lines"] == 1
    assert stats["node_types"]["finding"] == 1


def test_evidence_chain_reports_complete_chain(tmp_path):
    graph = EvidenceGraph(_case_dir(tmp_path))

    result = queries.evidence_chain(graph, "F-tester-001")

    assert result["chain_complete"] is True
    assert result["chain_length"] == 2
    assert result["chain"][0]["relation"] == "cites"
    assert result["chain"][1]["to"] == "E-tester-001"


def test_temporal_neighbors_and_host_summary(tmp_path):
    graph = EvidenceGraph(_case_dir(tmp_path))

    neighbors = queries.temporal_neighbors(graph, "2024-03-15T14:32:07Z", 60)
    summary = queries.host_summary(graph, "NFURY")

    assert [n["id"] for n in neighbors["neighbors"]] == [
        "F-tester-001",
        "T-tester-001",
    ]
    assert neighbors["cross_host_activity"] is False
    assert summary["findings_count"] == 1
    assert summary["timeline_events_count"] == 1
    assert summary["iocs_count"] == 1
    assert summary["evidence_files"] == 1
    assert summary["accounts_involved"] == ["SHIELDBASE\\nromanoff"]


def test_corroboration_and_cross_reference(tmp_path):
    graph = EvidenceGraph(_case_dir(tmp_path))

    corroboration = queries.corroboration_map(graph, "F-tester-001")
    xref = queries.cross_reference(graph, "mimikatz.exe")

    assert corroboration["corroboration"] == "PARTIAL"
    assert corroboration["sources"]["unique_evidence_files"] == 1
    assert xref["total_matches"] >= 1
    assert "NFURY" in xref["hosts_seen_on"]


def test_evidence_chain_reports_missing_audit_gap(tmp_path):
    case_dir = _case_dir(tmp_path)
    findings = json.loads((case_dir / "findings.json").read_text())
    findings[0]["audit_ids"] = ["missing-audit-id"]
    _write_json(case_dir / "findings.json", findings)
    graph = EvidenceGraph(case_dir)

    result = queries.evidence_chain(graph, "F-tester-001")

    assert result["chain_complete"] is False
    assert result["gaps"][0]["missing"] == "missing-audit-id"
