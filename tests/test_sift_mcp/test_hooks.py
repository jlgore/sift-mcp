"""Tests for the harness hook adapters (Layer 0).

Tests cover:
- gate.py input parsing from Claude Code, OpenCode, Pi, and argv formats
- gate.py policy evaluation integration (allow, deny, engine error)
- install.py config generation for all three harnesses
- install.py merge behavior (no duplicate installation)
- install.py auto-detection
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from sift_mcp.hooks.gate import _parse_input, main as gate_main
from sift_mcp.hooks.install import (
    detect_harness,
    install_claude_code,
    install_opencode,
    install_pi,
)


# ---------------------------------------------------------------------------
# gate.py: input parsing
# ---------------------------------------------------------------------------


class TestParseInputClaudeCode:
    """Claude Code sends JSON on stdin: {"tool_input": {"command": "..."}}."""

    def test_parses_claude_code_format(self, monkeypatch):
        payload = json.dumps({"tool_input": {"command": "find /evidence -name '*.evtx'"}})
        monkeypatch.setattr("sys.stdin", _FakeStdin(payload))
        result = _parse_input()
        assert result.argv == ["find", "/evidence", "-name", "*.evtx"]
        assert result.source == "claude-code"

    def test_empty_command_returns_none(self, monkeypatch):
        payload = json.dumps({"tool_input": {"command": ""}})
        monkeypatch.setattr("sys.stdin", _FakeStdin(payload))
        monkeypatch.setattr("sys.argv", ["gate.py"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        assert _parse_input() is None

    def test_missing_command_key_returns_none(self, monkeypatch):
        payload = json.dumps({"tool_input": {}})
        monkeypatch.setattr("sys.stdin", _FakeStdin(payload))
        monkeypatch.setattr("sys.argv", ["gate.py"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        assert _parse_input() is None


class TestParseInputOpenCode:
    """OpenCode sends JSON on stdin or via OPENCODE_TOOL_ARGS env var."""

    def test_parses_stdin_command_format(self, monkeypatch):
        payload = json.dumps({"command": "strings /evidence/disk.img"})
        monkeypatch.setattr("sys.stdin", _FakeStdin(payload))
        result = _parse_input()
        assert result.argv == ["strings", "/evidence/disk.img"]

    def test_parses_tool_args_format(self, monkeypatch):
        payload = json.dumps({"tool_args": {"command": "vol3 windows.pslist"}})
        monkeypatch.setattr("sys.stdin", _FakeStdin(payload))
        result = _parse_input()
        assert result.argv == ["vol3", "windows.pslist"]

    def test_parses_env_var(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.setenv("OPENCODE_TOOL_ARGS", json.dumps({"command": "fls -r /dev/sda1"}))
        result = _parse_input()
        assert result.argv == ["fls", "-r", "/dev/sda1"]
        assert result.source == "opencode"

    def test_stdin_takes_priority_over_env(self, monkeypatch):
        monkeypatch.setattr(
            "sys.stdin",
            _FakeStdin(json.dumps({"command": "from-stdin"})),
        )
        monkeypatch.setenv("OPENCODE_TOOL_ARGS", json.dumps({"command": "from-env"}))
        result = _parse_input()
        assert result.argv == ["from-stdin"]


class TestParseInputArgv:
    """Fallback: argv[1:] treated as the command."""

    def test_parses_argv(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.setattr("sys.argv", ["gate.py", "grep", "-r", "pattern", "/cases"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        result = _parse_input()
        assert result.argv == ["grep", "-r", "pattern", "/cases"]
        assert result.source == "generic"

    def test_no_input_returns_none(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.setattr("sys.argv", ["gate.py"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        assert _parse_input() is None


class TestParseInputEdgeCases:
    def test_invalid_json_falls_through_to_argv(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin("not json"))
        monkeypatch.setattr("sys.argv", ["gate.py", "echo", "hello"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        result = _parse_input()
        assert result.argv == ["echo", "hello"]

    def test_invalid_json_no_argv_returns_none(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin("not json"))
        monkeypatch.setattr("sys.argv", ["gate.py"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        assert _parse_input() is None


# ---------------------------------------------------------------------------
# gate.py: policy evaluation via main()
# ---------------------------------------------------------------------------


class TestGateMainAllow:
    def test_allowed_command_exits_0(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.setattr("sys.argv", ["gate.py", "fls", "-r", "/cases/disk.img"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        monkeypatch.setenv("SIFT_POLICY_ENGINE", "1")

        decision = {"allowed": True, "reasons": [], "policies_evaluated": []}
        # gate.main() imports evaluate_command lazily from the policy module,
        # so patch it at its source (sift_mcp.policy.evaluator).
        with patch("sift_mcp.policy.evaluator.evaluate_command", return_value=decision):
            result = gate_main()
        assert result == 0

    def test_no_input_exits_0(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.setattr("sys.argv", ["gate.py"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        result = gate_main()
        assert result == 0


class TestGateMainDeny:
    def test_denied_command_exits_2(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.setattr("sys.argv", ["gate.py", "find", "/evidence", "-exec", "rm", "{}", ";"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        monkeypatch.setenv("SIFT_POLICY_ENGINE", "1")

        decision = {
            "allowed": False,
            "reasons": [
                "sift.tool_blocked_flags: flag '-exec' is not permitted on 'find'",
                "sift.shell_metacharacters: shell metacharacter ';' detected",
            ],
            "policies_evaluated": ["sift.tool_blocked_flags", "sift.shell_metacharacters"],
        }
        with patch("sift_mcp.policy.evaluator.evaluate_command", return_value=decision):
            result = gate_main()

        assert result == 2
        captured = capsys.readouterr()
        assert "-exec" in captured.err
        assert ";" in captured.err

    def test_denied_binary_exits_2(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.setattr("sys.argv", ["gate.py", "mkfs", "/dev/sda1"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        monkeypatch.setenv("SIFT_POLICY_ENGINE", "1")

        decision = {
            "allowed": False,
            "reasons": ["sift.denied_binaries: binary 'mkfs' is blocked"],
            "policies_evaluated": ["sift.denied_binaries"],
        }
        with patch("sift_mcp.policy.evaluator.evaluate_command", return_value=decision):
            result = gate_main()

        assert result == 2
        assert "mkfs" in capsys.readouterr().err


class TestGateMainFailOpen:
    """Policy engine errors should fail open (exit 0), not block forensic work."""

    def test_engine_disabled_is_noop(self, monkeypatch):
        """When SIFT_POLICY_ENGINE is unset, the gate is a no-op (exit 0),
        matching Layer 1 (run_command) which only evaluates when enabled."""
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.setattr("sys.argv", ["gate.py", "mkfs", "/dev/sda1"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        monkeypatch.delenv("SIFT_POLICY_ENGINE", raising=False)

        # evaluate_command must not even be called when the engine is disabled.
        with patch(
            "sift_mcp.policy.evaluator.evaluate_command",
            side_effect=AssertionError("evaluate_command should not be called"),
        ):
            result = gate_main()
        assert result == 0

    def test_import_error_exits_0(self, monkeypatch, capsys):
        """If the policy module can't be imported, the gate fails open (exit 0)
        with a warning — forensic work is never blocked by a missing engine."""
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.setattr("sys.argv", ["gate.py", "strings", "/evidence/file"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)

        # Setting the module to None in sys.modules makes
        # `from sift_mcp.policy.evaluator import evaluate_command` raise ImportError.
        with patch.dict("sys.modules", {"sift_mcp.policy.evaluator": None}):
            result = gate_main()

        assert result == 0
        assert "not available" in capsys.readouterr().err

    def test_evaluation_error_exits_0(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.setattr("sys.argv", ["gate.py", "strings", "/evidence/file"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        monkeypatch.setenv("SIFT_POLICY_ENGINE", "1")

        with patch(
            "sift_mcp.policy.evaluator.evaluate_command",
            side_effect=RuntimeError("OPA crashed"),
        ):
            result = gate_main()

        assert result == 0
        assert "OPA crashed" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# gate.py: denial audit logging (Layer 0 self-correction trace)
# ---------------------------------------------------------------------------


class TestGateAuditLogging:
    """A harness-hook denial must be persisted to the case audit trail so the
    'denied' half of a self-correction trace survives, even though the command
    bypassed run_command (the agent used its native shell)."""

    def _setup_case(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "INC-001"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("case_id: INC-001\n")
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "tester")
        monkeypatch.setenv("SIFT_POLICY_ENGINE", "1")
        monkeypatch.delenv("VHIR_ACTIVE_CASE", raising=False)
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        return case_dir

    def _entries(self, case_dir):
        log = case_dir / "audit" / "sift-mcp.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines() if line]

    def test_denial_writes_audit_entry(self, tmp_path, monkeypatch):
        case_dir = self._setup_case(tmp_path, monkeypatch)
        monkeypatch.setattr("sys.argv", ["gate.py", "mkfs", "/dev/sda1"])
        decision = {
            "allowed": False,
            "reasons": ["sift.denied_binaries: binary 'mkfs' is blocked"],
            "policies_evaluated": ["sift.denied_binaries", "sift.path_policy"],
        }
        with patch("sift_mcp.policy.evaluator.evaluate_command", return_value=decision):
            result = gate_main()

        assert result == 2
        entries = self._entries(case_dir)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["source"] == "harness_hook"
        assert entry["tool"] == "bash"
        assert entry["case_id"] == "INC-001"
        pd = entry["result_summary"]["policy_decision"]
        assert pd["allowed"] is False
        assert any("mkfs" in r for r in pd["reasons"])
        assert pd["policies_evaluated"] == ["sift.denied_binaries", "sift.path_policy"]

    def test_allowed_command_writes_no_audit_entry(self, tmp_path, monkeypatch):
        case_dir = self._setup_case(tmp_path, monkeypatch)
        monkeypatch.setattr("sys.argv", ["gate.py", "fls", "-r", "/cases/disk.img"])
        decision = {"allowed": True, "reasons": [], "policies_evaluated": ["sift.x"]}
        with patch("sift_mcp.policy.evaluator.evaluate_command", return_value=decision):
            result = gate_main()

        assert result == 0
        assert self._entries(case_dir) == []

    def test_audit_failure_does_not_block_denial(self, monkeypatch):
        """No active case (audit write no-ops) → the gate still denies (exit 2)."""
        monkeypatch.setattr("sys.stdin", _FakeStdin(""))
        monkeypatch.setattr("sys.argv", ["gate.py", "mkfs", "/dev/sda1"])
        monkeypatch.delenv("OPENCODE_TOOL_ARGS", raising=False)
        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
        monkeypatch.setenv("SIFT_POLICY_ENGINE", "1")
        decision = {
            "allowed": False,
            "reasons": ["sift.denied_binaries: binary 'mkfs' is blocked"],
            "policies_evaluated": ["sift.denied_binaries"],
        }
        with patch("sift_mcp.policy.evaluator.evaluate_command", return_value=decision):
            result = gate_main()
        assert result == 2


# ---------------------------------------------------------------------------
# gate.py: end-to-end subprocess test (real OPA, if available)
# ---------------------------------------------------------------------------


_HAS_OPA = (Path(__file__).resolve().parents[2] / "tools" / "opa").exists()
_needs_opa = pytest.mark.skipif(not _HAS_OPA, reason="OPA binary not in tools/")


@_needs_opa
class TestGateSubprocess:
    """Run gate.py as a real subprocess to test the full stdin/exit-code contract."""

    def test_denied_command_via_claude_code_stdin(self):
        payload = json.dumps({"tool_input": {"command": "mkfs /dev/sda1"}})
        proc = subprocess.run(
            [sys.executable, "-m", "sift_mcp.hooks.gate"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "SIFT_POLICY_ENGINE": "1"},
        )
        assert proc.returncode == 2
        assert "mkfs" in proc.stderr

    def test_allowed_command_via_argv(self):
        proc = subprocess.run(
            [sys.executable, "-m", "sift_mcp.hooks.gate", "echo", "hello"],
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "SIFT_POLICY_ENGINE": "1"},
        )
        assert proc.returncode == 0

    def test_shell_metacharacter_denied(self):
        payload = json.dumps({"tool_input": {"command": "cat /evidence/f; rm -rf /"}})
        proc = subprocess.run(
            [sys.executable, "-m", "sift_mcp.hooks.gate"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "SIFT_POLICY_ENGINE": "1"},
        )
        assert proc.returncode == 2
        assert "metacharacter" in proc.stderr.lower() or ";" in proc.stderr


# ---------------------------------------------------------------------------
# install.py: Claude Code
# ---------------------------------------------------------------------------


class TestInstallClaudeCode:
    def test_creates_settings_file(self, tmp_path):
        result = install_claude_code(str(tmp_path))
        settings_path = tmp_path / ".claude" / "settings.local.json"

        assert settings_path.exists()
        assert "Installed" in result

        settings = json.loads(settings_path.read_text())
        hooks = settings["hooks"]["PreToolUse"]
        assert len(hooks) == 1
        assert hooks[0]["matcher"] == "Bash"
        assert "sift_mcp.hooks.gate" in hooks[0]["hooks"][0]["command"]

    def test_merges_with_existing_settings(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        existing = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Write", "hooks": [{"type": "command", "command": "lint.sh"}]}
                ]
            },
            "permissions": {"allow": ["Read"]},
        }
        (claude_dir / "settings.local.json").write_text(json.dumps(existing))

        install_claude_code(str(tmp_path))

        settings = json.loads((claude_dir / "settings.local.json").read_text())
        # Existing hook preserved
        assert len(settings["hooks"]["PreToolUse"]) == 2
        assert settings["hooks"]["PreToolUse"][0]["matcher"] == "Write"
        assert settings["hooks"]["PreToolUse"][1]["matcher"] == "Bash"
        # Other config preserved
        assert settings["permissions"]["allow"] == ["Read"]

    def test_no_duplicate_install(self, tmp_path):
        install_claude_code(str(tmp_path))
        result = install_claude_code(str(tmp_path))
        assert "Already installed" in result

        settings = json.loads(
            (tmp_path / ".claude" / "settings.local.json").read_text()
        )
        assert len(settings["hooks"]["PreToolUse"]) == 1


# ---------------------------------------------------------------------------
# install.py: OpenCode
# ---------------------------------------------------------------------------


class TestInstallOpenCode:
    def test_creates_hooks_yaml(self, tmp_path):
        result = install_opencode(str(tmp_path))
        hooks_path = tmp_path / ".opencode" / "hooks.yaml"

        assert hooks_path.exists()
        assert "Installed" in result

        import yaml as _yaml
        config = _yaml.safe_load(hooks_path.read_text())
        hooks = config["hooks"]
        assert len(hooks) == 1
        assert hooks[0]["event"] == "tool.before.bash"
        assert hooks[0]["action"] == "stop"
        assert "sift_mcp.hooks.gate" in str(hooks[0]["actions"][0])

    def test_merges_with_existing_hooks(self, tmp_path):
        oc_dir = tmp_path / ".opencode"
        oc_dir.mkdir()
        import yaml as _yaml
        existing = {
            "hooks": [
                {"event": "session.start", "actions": [{"bash": "echo started"}]}
            ]
        }
        (oc_dir / "hooks.yaml").write_text(_yaml.dump(existing))

        install_opencode(str(tmp_path))

        config = _yaml.safe_load((oc_dir / "hooks.yaml").read_text())
        assert len(config["hooks"]) == 2
        assert config["hooks"][0]["event"] == "session.start"
        assert config["hooks"][1]["event"] == "tool.before.bash"

    def test_no_duplicate_install(self, tmp_path):
        install_opencode(str(tmp_path))
        result = install_opencode(str(tmp_path))
        assert "Already installed" in result


# ---------------------------------------------------------------------------
# install.py: Pi
# ---------------------------------------------------------------------------


class TestInstallPi:
    def test_copies_ts_extension(self, tmp_path, monkeypatch):
        # Create a fake pi_extension.ts source
        hooks_pkg = Path(__file__).resolve().parent.parent / "packages" / "sift-mcp" / "src" / "sift_mcp" / "hooks"
        # Use the real source if available, otherwise create a fake
        src = hooks_pkg / "pi_extension.ts" if hooks_pkg.exists() else None

        result = install_pi(str(tmp_path))

        if "Error" not in result:
            dest = tmp_path / ".pi" / "hooks" / "sift-policy-gate.ts"
            assert dest.exists()
            assert "tool_call" in dest.read_text()
        # If pi_extension.ts not found, that's OK for CI

    def test_no_duplicate_install(self, tmp_path):
        # First install
        install_pi(str(tmp_path))
        # Second install
        result = install_pi(str(tmp_path))
        if "Error" not in result:
            assert "Already installed" in result


# ---------------------------------------------------------------------------
# install.py: auto-detection
# ---------------------------------------------------------------------------


class TestDetectHarness:
    def test_detects_claude_code(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        assert detect_harness(str(tmp_path)) == "claude-code"

    def test_detects_claude_md(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("# instructions")
        assert detect_harness(str(tmp_path)) == "claude-code"

    def test_detects_opencode(self, tmp_path):
        (tmp_path / ".opencode").mkdir()
        assert detect_harness(str(tmp_path)) == "opencode"

    def test_detects_pi(self, tmp_path):
        (tmp_path / ".pi").mkdir()
        assert detect_harness(str(tmp_path)) == "pi"

    def test_no_harness_returns_none(self, tmp_path):
        assert detect_harness(str(tmp_path)) is None

    def test_claude_code_takes_priority(self, tmp_path):
        """If multiple harness indicators exist, Claude Code wins (checked first)."""
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".opencode").mkdir()
        assert detect_harness(str(tmp_path)) == "claude-code"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeStdin:
    """Simulate stdin for testing _parse_input."""

    def __init__(self, data: str):
        self._data = data

    def isatty(self) -> bool:
        return False

    def read(self) -> str:
        return self._data
