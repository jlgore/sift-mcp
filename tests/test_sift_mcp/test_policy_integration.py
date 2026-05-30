"""Integration tests: OPA policy gate wired into run_command.

Exercises the real OPA binary (repo tools/opa) against the compiled default
security.yaml. The gate is enabled via SIFT_POLICY_ENGINE; when disabled, the
legacy security.py path must remain the sole enforcement (no-op proof).
"""

from unittest.mock import patch

import pytest
from sift_mcp.catalog import clear_catalog_cache
from sift_mcp.exceptions import DeniedBinaryError, PolicyDenialError
from sift_mcp.policy.evaluator import reset_evaluator
from sift_mcp.tools.generic import run_command


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    clear_catalog_cache()
    reset_evaluator()
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    yield
    clear_catalog_cache()
    reset_evaluator()


@pytest.fixture
def engine_on(monkeypatch):
    monkeypatch.setenv("SIFT_POLICY_ENGINE", "1")


class TestPolicyGateEnabled:
    def test_find_exec_denied_with_all_reasons(self, engine_on):
        with pytest.raises(PolicyDenialError) as exc:
            run_command(["find", "/evidence", "-exec", "rm", "{}", ";"])
        decision = exc.value.decision
        assert decision["allowed"] is False
        reasons = " ".join(decision["reasons"])
        assert "-exec" in reasons
        assert "shell metacharacter" in reasons
        # Headline feature: more than one reason returned at once.
        assert len(decision["reasons"]) >= 2

    def test_denied_binary_returns_policy_denial(self, engine_on):
        # With the engine on, OPA denies first → PolicyDenialError (carries the
        # structured decision) rather than the bare DeniedBinaryError.
        with pytest.raises(PolicyDenialError) as exc:
            run_command(["mkfs", "/dev/sda1"])
        assert any("blocked by security policy" in r for r in exc.value.decision["reasons"])

    def test_rm_protected_dir_denied(self, engine_on):
        with pytest.raises(PolicyDenialError) as exc:
            run_command(["rm", "-rf", "/cases"])
        assert any("protected directory" in r for r in exc.value.decision["reasons"])

    def test_allowed_command_falls_through_to_execution(self, engine_on):
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
            out = run_command(["echo", "hi"])
        assert out["exit_code"] == 0

    def test_decision_lists_policies_evaluated(self, engine_on):
        with pytest.raises(PolicyDenialError) as exc:
            run_command(["sed", "-i", "s/a/b/", "/cases/f.txt"])
        # Every category is reported as evaluated, not just the one that fired.
        assert len(exc.value.decision["policies_evaluated"]) >= 7


class TestPolicyGateDisabled:
    """With the engine off (default), security.py is the only enforcement."""

    def test_denied_binary_uses_legacy_path(self):
        # No SIFT_POLICY_ENGINE → DeniedBinaryError from security.py, NOT
        # PolicyDenialError.
        with pytest.raises(DeniedBinaryError):
            run_command(["mkfs", "/dev/sda1"])

    def test_legacy_rm_protection_still_active(self):
        with pytest.raises(ValueError):
            run_command(["rm", "-rf", "/cases"])
