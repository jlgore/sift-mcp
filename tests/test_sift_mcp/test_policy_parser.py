"""Tests for sift_mcp.policy.parser — run_command -> OPA input document.

These pin the parser to the existing security.py semantics: an argument the
live pipeline would treat as an input path must land in ``paths``, an output
path in ``output_paths``, a /dev device specifier (for disk-forensics tools)
in ``device_paths``, and blocked/dangerous flags must be discoverable in
``flags``.
"""

from pathlib import Path

import pytest
from sift_mcp.catalog import clear_catalog_cache
from sift_mcp.policy.parser import build_input_doc


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_catalog_cache()
    yield
    clear_catalog_cache()


def _resolved(p: str) -> str:
    return str(Path(p).resolve())


class TestBasics:
    def test_empty_command_raises(self):
        with pytest.raises(ValueError, match="Empty command"):
            build_input_doc([])

    def test_tool_is_basename(self):
        doc = build_input_doc(["/usr/sbin/mkfs", "/dev/sda1"])
        assert doc["tool"] == "mkfs"

    def test_raw_command_preserves_original(self):
        doc = build_input_doc(["find", "/cases", "-name", "*.log"])
        assert doc["raw_command"] == "find /cases -name *.log"

    def test_args_excludes_binary(self):
        doc = build_input_doc(["strings", "-n", "8", "/cases/x"])
        assert doc["args"] == ["-n", "8", "/cases/x"]


class TestFlags:
    def test_collects_dash_flags(self):
        doc = build_input_doc(["find", "/cases", "-name", "*.log", "-exec", "x", ";"])
        assert "-exec" in doc["flags"]
        assert "-name" in doc["flags"]

    def test_normalizes_flag_equals_value(self):
        doc = build_input_doc(["tool", "--output=/tmp/o.csv"])
        # The flag form must be discoverable as "--output", not "--output=/tmp/o.csv"
        assert "--output" in doc["flags"]
        assert "--output=/tmp/o.csv" not in doc["flags"]

    def test_positionals_are_not_flags(self):
        doc = build_input_doc(["sed", "s/foo/bar/", "/cases/file.txt"])
        assert doc["flags"] == []

    def test_dangerous_flag_present(self):
        doc = build_input_doc(["sometool", "-e", "payload"])
        assert "-e" in doc["flags"]


class TestShellMetacharacterVisibility:
    def test_semicolon_arg_visible(self):
        # The shell_metacharacters Rego rule scans input.args, so ';' must survive.
        doc = build_input_doc(["find", "/cases", "-exec", "rm", "{}", ";"])
        assert ";" in doc["args"]

    def test_command_substitution_arg_visible(self):
        doc = build_input_doc(["sometool", "$(whoami)"])
        assert "$(whoami)" in doc["args"]


class TestInputPaths:
    def test_positional_path_is_input(self):
        doc = build_input_doc(["fls", "-r", "/evidence/disk.img"])
        assert doc["paths"] == [_resolved("/evidence/disk.img")]
        assert doc["output_paths"] == []

    def test_blocked_system_path_lands_in_paths(self):
        # /etc input is blocked by path_policy; parser must surface it.
        doc = build_input_doc(["strings", "/etc/shadow"])
        assert _resolved("/etc/shadow") in doc["paths"]

    def test_flag_equals_value_input_path(self):
        doc = build_input_doc(["tool", "--input=/cases/evidence.img"])
        assert doc["paths"] == [_resolved("/cases/evidence.img")]
        assert doc["output_paths"] == []

    def test_non_path_args_ignored(self):
        doc = build_input_doc(["find", "/cases", "-name", "*.evtx", "-type", "f"])
        assert doc["paths"] == [_resolved("/cases")]


class TestOutputPaths:
    def test_output_flag_then_path(self):
        doc = build_input_doc(["tool", "-o", "/tmp/out.csv"])
        assert doc["output_paths"] == [_resolved("/tmp/out.csv")]
        assert doc["paths"] == []

    def test_csv_output_flag(self):
        doc = build_input_doc(["tool", "--csv", "/cases/c1/report.csv"])
        assert doc["output_paths"] == [_resolved("/cases/c1/report.csv")]

    def test_flag_equals_value_output_path(self):
        doc = build_input_doc(["tool", "--output=/tmp/o.csv"])
        assert doc["output_paths"] == [_resolved("/tmp/o.csv")]
        assert doc["paths"] == []

    def test_input_and_output_together(self):
        doc = build_input_doc(["tool", "/cases/in.img", "-o", "/tmp/out.csv"])
        assert doc["paths"] == [_resolved("/cases/in.img")]
        assert doc["output_paths"] == [_resolved("/tmp/out.csv")]


class TestDevicePaths:
    def test_dev_tool_gets_device_path(self):
        doc = build_input_doc(["fls", "/dev/sda1"])
        assert doc["device_paths"] == ["/dev/sda1"]
        assert doc["paths"] == []

    def test_non_dev_tool_dev_path_is_input(self):
        # strings is NOT a disk-forensics tool: /dev/sda is a blocked input,
        # so it must land in paths for path_policy to reject it.
        doc = build_input_doc(["strings", "/dev/sda"])
        assert _resolved("/dev/sda") in doc["paths"]
        assert doc["device_paths"] == []

    def test_dev_tool_non_dev_path_is_input(self):
        doc = build_input_doc(["fls", "/evidence/disk.img"])
        assert doc["paths"] == [_resolved("/evidence/disk.img")]
        assert doc["device_paths"] == []


class TestRmTargets:
    def test_rm_target_in_paths(self):
        doc = build_input_doc(["rm", "-rf", "/cases"])
        assert _resolved("/cases") in doc["paths"]

    def test_rm_root_in_paths(self):
        doc = build_input_doc(["rm", "-rf", "/"])
        assert "/" in doc["paths"]

    def test_rm_flags_not_treated_as_paths(self):
        doc = build_input_doc(["rm", "-rf"])
        assert doc["paths"] == []

    def test_rm_relative_target_resolved(self):
        # Unlike the generic heuristic, rm captures no-slash relative targets.
        doc = build_input_doc(["rm", "evidence.txt"])
        assert doc["paths"] == [_resolved("evidence.txt")]

    def test_rm_multiple_targets(self):
        doc = build_input_doc(["rm", "/cases/a", "/tmp/b"])
        assert _resolved("/cases/a") in doc["paths"]
        assert _resolved("/tmp/b") in doc["paths"]


class TestContextMerge:
    def test_context_fields_merged(self):
        doc = build_input_doc(
            ["fls", "/evidence/x"],
            context={"case_id": "INC-2026-001", "sandbox_enabled": True},
        )
        assert doc["case_id"] == "INC-2026-001"
        assert doc["sandbox_enabled"] is True
        assert doc["tool"] == "fls"

    def test_command_keys_win_over_context(self):
        doc = build_input_doc(["fls", "/evidence/x"], context={"tool": "spoofed"})
        assert doc["tool"] == "fls"


class TestPrdCanonicalDenialCase:
    """The PRD's headline case: find -exec rm {} ; -> two independent reasons."""

    def test_find_exec_semicolon(self):
        doc = build_input_doc(
            ["find", "/evidence", "-exec", "rm", "{}", ";"]
        )
        assert doc["tool"] == "find"
        assert "-exec" in doc["flags"]  # tool_blocked_flags will fire
        assert ";" in doc["args"]  # shell_metacharacters will fire
        assert _resolved("/evidence") in doc["paths"]
