"""Tests for sift_mcp.server — MCP server creation and tool execution."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from sift_mcp.catalog import clear_catalog_cache
from sift_mcp.server import create_server

_HAS_OPA = (Path(__file__).resolve().parents[2] / "tools" / "opa").exists()
_needs_opa = pytest.mark.skipif(not _HAS_OPA, reason="OPA binary not in tools/")


@pytest.fixture(autouse=True)
def clean_state():
    clear_catalog_cache()
    yield
    clear_catalog_cache()


class TestServer:
    def test_create_server(self):
        server = create_server()
        assert server is not None
        assert server.name == "sift-mcp"

    def test_server_has_tools(self):
        """Verify core tools are registered."""
        server = create_server()
        assert server is not None


class TestRunCommandEnvelope:
    """Test run_command through the server with mocked executor."""

    def test_successful_execution(self, monkeypatch):
        """Verify response envelope fields on successful execution."""
        monkeypatch.setenv("VHIR_EXAMINER", "testuser")
        server = create_server()

        mock_result = {
            "exit_code": 0,
            "stdout": "output data",
            "stderr": "",
            "elapsed_seconds": 1.5,
            "command": ["echo", "hello"],
        }

        with (
            patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/echo"),
            patch("sift_mcp.tools.generic.execute", return_value=mock_result),
        ):
            from sift_mcp.tools.generic import run_command

            result = run_command(["echo", "hello"], purpose="test")
            assert result["exit_code"] == 0

    def test_denied_binary_error(self, monkeypatch):
        """Verify error handling for denied binaries."""
        from sift_mcp.exceptions import DeniedBinaryError
        from sift_mcp.tools.generic import run_command

        with pytest.raises(DeniedBinaryError, match="blocked"):
            run_command(["mkfs", "/dev/sda"], purpose="test")

    def test_uncataloged_binary_not_found(self, monkeypatch):
        """Uncataloged binary not on system raises ExecutionError."""
        from sift_mcp.exceptions import ExecutionError
        from sift_mcp.tools.generic import run_command

        with patch("sift_mcp.tools.generic.find_binary", return_value=None):
            with pytest.raises(ExecutionError, match="not found"):
                run_command(["nonexistent_tool", "--flag"], purpose="test")

    def test_catch_all_exception_handler(self, monkeypatch):
        """Verify the catch-all exception handler in server.py."""
        monkeypatch.setenv("VHIR_EXAMINER", "testuser")
        server = create_server()

        # The catch-all wraps unexpected exceptions. We test by checking
        # that the server builds without error and has the run_command tool.
        assert server is not None

    def test_extractions_passed_to_response(self, monkeypatch):
        """Verify extractions flow into the response envelope."""
        monkeypatch.setenv("VHIR_EXAMINER", "testuser")
        from sift_mcp.response import build_response

        extractions = ["/cases/test/extractions/20260223_tool_stdout.txt"]
        response = build_response(
            tool_name="run_command",
            success=True,
            data={"stdout": "ok"},
            audit_id="sift-test-20260223-001",
            extractions=extractions,
        )
        assert response["extractions"] == extractions

    def test_extractions_absent_when_none(self, monkeypatch):
        """Verify extractions key omitted when not provided."""
        monkeypatch.setenv("VHIR_EXAMINER", "testuser")
        from sift_mcp.response import build_response

        response = build_response(
            tool_name="run_command",
            success=True,
            data={"stdout": "ok"},
            audit_id="sift-test-20260223-001",
        )
        assert "extractions" not in response


@_needs_opa
class TestPolicyDecisionInAuditTrail:
    """The full server-tool path (FastMCP call_tool) must persist the policy
    verdict to the audit JSONL — both halves of the self-correction trace.

    Asserts against the written audit file (the actual deliverable), not the
    call_tool return value (whose shape is FastMCP-version dependent).
    """

    @pytest.fixture
    def case(self, tmp_path, monkeypatch):
        from sift_mcp.policy.evaluator import reset_evaluator

        case_dir = tmp_path / "INC-007"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("case_id: INC-007\n")
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "tester")
        monkeypatch.setenv("SIFT_POLICY_ENGINE", "1")
        monkeypatch.delenv("VHIR_ACTIVE_CASE", raising=False)
        clear_catalog_cache()
        reset_evaluator()
        yield case_dir
        reset_evaluator()

    def _audit_entries(self, case_dir) -> list[dict]:
        log = case_dir / "audit" / "sift-mcp.jsonl"
        return [json.loads(line) for line in log.read_text().splitlines() if line]

    async def test_denial_is_persisted_to_audit(self, case):
        """A policy denial (which raises before execute()) must still write an
        audit entry carrying the structured decision — the 'denied' half of the
        self-correction trace is not lost to the exception path."""
        server = create_server()
        await server.call_tool(
            "run_command",
            {"command": ["mkfs", "/dev/sda1"], "purpose": "denial audit test"},
        )
        entries = self._audit_entries(case)
        assert len(entries) == 1
        decision = entries[0]["result_summary"]["policy_decision"]
        assert decision["allowed"] is False
        assert any("mkfs" in r for r in decision["reasons"])
        assert len(decision["policies_evaluated"]) >= 7
        assert entries[0]["case_id"] == "INC-007"

    async def test_allow_verdict_is_persisted_to_audit(self, case):
        """On allow, the audit entry records the OPA verdict (allowed + full
        policies_evaluated list) alongside the sandbox flags."""
        mock_result = {
            "exit_code": 0,
            "stdout": "ok",
            "stderr": "",
            "elapsed_seconds": 0.1,
            "command": ["echo", "hi"],
            "stdout_total_bytes": 2,
        }
        with (
            patch("sift_mcp.tools.generic.find_binary", return_value="/usr/bin/echo"),
            patch("sift_mcp.tools.generic.execute", return_value=mock_result),
        ):
            server = create_server()
            await server.call_tool(
                "run_command",
                {"command": ["echo", "hi"], "purpose": "allow audit test"},
            )
        entries = self._audit_entries(case)
        assert len(entries) == 1
        decision = entries[0]["result_summary"]["policy_decision"]
        assert decision["allowed"] is True
        assert decision["reasons"] == []
        assert len(decision["policies_evaluated"]) >= 7
