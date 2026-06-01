"""Tests for shell command-line decomposition (harness gate Layer 1 depth)."""

import sys

import pytest

from sift_mcp.hooks import shell_decompose
from sift_mcp.hooks.shell_decompose import decompose_command_line


def _has(cmds, argv):
    return argv in cmds


class TestBashlexDecomposition:
    def test_simple_command(self):
        assert decompose_command_line("ls -la /evidence") == [["ls", "-la", "/evidence"]]

    def test_empty_is_no_commands(self):
        assert decompose_command_line("") == []
        assert decompose_command_line("   ") == []

    def test_pipeline_splits(self):
        cmds = decompose_command_line("cat a | grep b")
        assert _has(cmds, ["cat", "a"])
        assert _has(cmds, ["grep", "b"])

    def test_and_or_list_splits(self):
        cmds = decompose_command_line("cd /x && rm -rf /evidence")
        assert _has(cmds, ["cd", "/x"])
        assert _has(cmds, ["rm", "-rf", "/evidence"])

    def test_semicolon_splits(self):
        cmds = decompose_command_line("echo hi; mkfs /dev/sdb")
        assert _has(cmds, ["echo", "hi"])
        assert _has(cmds, ["mkfs", "/dev/sdb"])

    def test_quoted_operator_is_not_split(self):
        # The && lives inside a quoted string — it's a literal arg to echo,
        # NOT a command separator.
        cmds = decompose_command_line('echo "a && b"')
        assert cmds == [["echo", "a && b"]]

    def test_command_substitution_surfaces_inner(self):
        # The hidden rm inside $(...) must be collected as its own command.
        cmds = decompose_command_line("echo $(rm -rf /evidence)")
        assert _has(cmds, ["rm", "-rf", "/evidence"])

    def test_substitution_embedded_in_path_arg(self):
        cmds = decompose_command_line("cat /evidence/$(whoami)/f")
        assert _has(cmds, ["whoami"])

    def test_redirect_target_dropped_from_argv(self):
        cmds = decompose_command_line("grep foo f > /tmp/out")
        assert cmds == [["grep", "foo", "f"]]

    def test_env_assignment_stripped(self):
        cmds = decompose_command_line("FOO=bar rm x")
        assert cmds == [["rm", "x"]]

    def test_subshell(self):
        cmds = decompose_command_line("( cd /x && rm y )")
        assert _has(cmds, ["cd", "/x"])
        assert _has(cmds, ["rm", "y"])

    def test_pipeline_and_list_combined(self):
        cmds = decompose_command_line("cat a | grep b && rm -rf /evidence")
        assert _has(cmds, ["cat", "a"])
        assert _has(cmds, ["grep", "b"])
        assert _has(cmds, ["rm", "-rf", "/evidence"])


class TestShlexFallback:
    """When bashlex is unavailable, the shlex operator-split still chains."""

    @pytest.fixture
    def no_bashlex(self, monkeypatch):
        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __import__

        def fake_import(name, *args, **kwargs):
            if name == "bashlex":
                raise ImportError("bashlex disabled for test")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", fake_import)
        yield

    def test_fallback_splits_operators(self, no_bashlex):
        cmds = decompose_command_line("cd /x && rm -rf /evidence")
        assert _has(cmds, ["cd", "/x"])
        assert _has(cmds, ["rm", "-rf", "/evidence"])

    def test_fallback_respects_quotes(self, no_bashlex):
        cmds = decompose_command_line('echo "a && b"')
        assert cmds == [["echo", "a && b"]]

    def test_fallback_drops_redirect(self, no_bashlex):
        cmds = decompose_command_line("grep foo f > /tmp/out")
        assert cmds == [["grep", "foo", "f"]]

    def test_fallback_strips_assignment(self, no_bashlex):
        cmds = decompose_command_line("FOO=bar rm x")
        assert cmds == [["rm", "x"]]


class TestRobustness:
    def test_unbalanced_quotes_does_not_raise(self):
        # Must never raise — degrade to a best-effort split.
        result = decompose_command_line('echo "unterminated')
        assert isinstance(result, list)

    def test_internal_helpers(self):
        assert shell_decompose._is_assignment("FOO=bar")
        assert not shell_decompose._is_assignment("=bar")
        assert not shell_decompose._is_assignment("nota path/x")
        assert shell_decompose._strip_assignments(["A=1", "B=2", "rm", "x"]) == ["rm", "x"]
