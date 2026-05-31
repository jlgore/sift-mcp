"""Tests for the bwrap sandbox (Layer 2).

Construction tests run anywhere (they pass an existing binary as a stand-in for
bwrap). Execution tests exercise the real bwrap binary and are skipped where it
isn't installed.
"""

import shutil
import subprocess
import sys

import pytest
from sift_mcp.sandbox.bwrap import build_sandbox_prefix, load_profile

_HAS_BWRAP = shutil.which("bwrap") is not None
_needs_bwrap = pytest.mark.skipif(not _HAS_BWRAP, reason="bwrap not installed")

# Use a real existing binary as a stand-in so verify_bwrap() passes on hosts
# without bwrap, letting us assert on prefix construction.
_FAKE_BWRAP = sys.executable


def _pairs(prefix: list[str], flag: str) -> list[tuple[str, str]]:
    """Extract (src, dst) for every occurrence of a bind flag in the prefix."""
    out = []
    for i, tok in enumerate(prefix):
        if tok == flag and i + 2 < len(prefix):
            out.append((prefix[i + 1], prefix[i + 2]))
    return out


class TestProfileLoading:
    def test_default_profile_loads(self):
        prof = load_profile("default")
        assert prof["name"] == "default"
        assert "net" in prof["unshare"]

    def test_missing_profile_raises(self):
        from sift_mcp.exceptions import SandboxError

        with pytest.raises(SandboxError):
            load_profile("does-not-exist")


class TestPrefixConstruction:
    def test_ends_with_double_dash(self):
        prefix = build_sandbox_prefix(bwrap_path=_FAKE_BWRAP)
        assert prefix[-1] == "--"
        assert prefix[0] == _FAKE_BWRAP

    def test_input_path_is_readonly_identity_bind(self, tmp_path):
        ev = tmp_path / "evidence.img"
        ev.write_text("data")
        prefix = build_sandbox_prefix(
            input_paths=[str(ev)], bwrap_path=_FAKE_BWRAP
        )
        ro = _pairs(prefix, "--ro-bind")
        assert (str(ev), str(ev)) in ro  # identity bind, read-only

    def test_output_parent_is_readwrite_bind(self, tmp_path):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        out_file = out_dir / "report.csv"
        prefix = build_sandbox_prefix(
            output_paths=[str(out_file)], bwrap_path=_FAKE_BWRAP
        )
        rw = _pairs(prefix, "--bind")
        assert (str(out_dir), str(out_dir)) in rw

    def test_nonexistent_input_is_skipped(self, tmp_path):
        missing = tmp_path / "nope.img"
        prefix = build_sandbox_prefix(
            input_paths=[str(missing)], bwrap_path=_FAKE_BWRAP
        )
        ro = _pairs(prefix, "--ro-bind")
        assert all(src != str(missing) for src, _ in ro)

    def test_evidence_ro_bound_after_case_rw(self, tmp_path):
        """Ordering guarantee: evidence inside a writable case dir stays RO.

        The evidence --ro-bind must appear AFTER the case dir --bind so bwrap's
        later-wins semantics keep evidence read-only.
        """
        case_dir = tmp_path / "CASE-001"
        ev = case_dir / "evidence" / "disk.img"
        ev.parent.mkdir(parents=True)
        ev.write_text("data")

        prefix = build_sandbox_prefix(
            input_paths=[str(ev)],
            case_dir=str(case_dir),
            bwrap_path=_FAKE_BWRAP,
        )
        case_idx = prefix.index(str(case_dir))
        ev_idx = prefix.index(str(ev))
        assert ev_idx > case_idx

    def test_evidence_subdir_ro_bound_blocks_new_files(self, tmp_path):
        """The evidence subdir is RO-bound as a whole (not just referenced
        files), so creating a NEW file in evidence/ is blocked even when the
        case dir is RW-bound. Carve-out: evidence/extracted stays RW.
        """
        case_dir = tmp_path / "CASE-001"
        (case_dir / "evidence" / "extracted").mkdir(parents=True)
        (case_dir / "out").mkdir()

        prefix = build_sandbox_prefix(
            case_dir=str(case_dir),
            profile={
                "case_readonly_subdirs": ["evidence"],
                "case_readwrite_subdirs": ["evidence/extracted"],
            },
            bwrap_path=_FAKE_BWRAP,
        )
        ev_dir = str(case_dir / "evidence")
        extracted = str(case_dir / "evidence" / "extracted")
        case_idx = prefix.index(str(case_dir))
        # evidence/ is RO-bound, after the RW case-dir bind (later wins).
        assert (ev_dir, ev_dir) in _pairs(prefix, "--ro-bind")
        assert prefix.index(ev_dir) > case_idx
        # evidence/extracted is RW-carved AFTER the evidence RO bind (later wins).
        assert (extracted, extracted) in _pairs(prefix, "--bind")
        assert prefix.index(extracted) > prefix.index(ev_dir)

    def test_case_readonly_subdirs_skipped_when_absent(self, tmp_path):
        """A configured RO subdir that doesn't exist is silently skipped."""
        case_dir = tmp_path / "CASE-001"
        case_dir.mkdir()
        prefix = build_sandbox_prefix(
            case_dir=str(case_dir),
            profile={"case_readonly_subdirs": ["evidence"]},
            bwrap_path=_FAKE_BWRAP,
        )
        assert str(case_dir / "evidence") not in prefix

    def test_network_isolated_by_default_profile(self):
        prefix = build_sandbox_prefix(bwrap_path=_FAKE_BWRAP)
        assert "--unshare-net" in prefix


class TestEnvSetenv:
    def test_profile_env_emits_sorted_setenv(self):
        prof = {"env": {"TMPDIR": "/tmp", "HOME": "/tmp", "DOTNET_NOLOGO": "1"}}
        prefix = build_sandbox_prefix(profile=prof, bwrap_path=_FAKE_BWRAP)
        setenv = _pairs(prefix, "--setenv")
        # all pairs present, emitted in sorted key order for stable output
        assert setenv == [("DOTNET_NOLOGO", "1"), ("HOME", "/tmp"), ("TMPDIR", "/tmp")]

    def test_no_env_means_no_setenv(self):
        # Back-compat: a profile without `env` emits zero --setenv flags.
        prefix = build_sandbox_prefix(profile={"unshare": ["net"]}, bwrap_path=_FAKE_BWRAP)
        assert "--setenv" not in prefix

    def test_setenv_values_coerced_to_str(self):
        prefix = build_sandbox_prefix(
            profile={"env": {"DOTNET_CLI_TELEMETRY_OPTOUT": 1}}, bwrap_path=_FAKE_BWRAP
        )
        assert _pairs(prefix, "--setenv") == [("DOTNET_CLI_TELEMETRY_OPTOUT", "1")]

    def test_default_profile_has_hygiene_env(self):
        prof = load_profile("default")
        assert prof["env"]["DOTNET_CLI_TELEMETRY_OPTOUT"] == "1"


@_needs_bwrap
class TestRealSandboxExecution:
    """Run actual commands through bwrap (the heart of the kernel-block demo)."""

    def test_read_evidence_succeeds(self, tmp_path):
        ev = tmp_path / "evidence.txt"
        ev.write_text("secret-evidence")
        prefix = build_sandbox_prefix(input_paths=[str(ev)])
        proc = subprocess.run(
            [*prefix, "cat", str(ev)], capture_output=True, text=True
        )
        assert proc.returncode == 0
        assert "secret-evidence" in proc.stdout

    def test_write_evidence_blocked_at_kernel(self, tmp_path):
        ev = tmp_path / "evidence.txt"
        ev.write_text("secret-evidence")
        prefix = build_sandbox_prefix(input_paths=[str(ev)])
        proc = subprocess.run(
            [*prefix, "touch", str(ev)], capture_output=True, text=True
        )
        assert proc.returncode != 0
        assert "Read-only file system" in proc.stderr

    def test_network_unshared(self):
        prefix = build_sandbox_prefix()
        proc = subprocess.run(
            [*prefix, "getent", "hosts", "example.com"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode != 0  # no DNS/network inside the namespace


@_needs_bwrap
class TestRunCommandSandboxed:
    """End-to-end: run_command executes inside the sandbox when enabled."""

    def test_echo_runs_in_sandbox(self, monkeypatch):
        from sift_mcp.catalog import clear_catalog_cache
        from sift_mcp.tools.generic import run_command

        clear_catalog_cache()
        monkeypatch.setenv("SIFT_SANDBOX", "1")
        out = run_command(["echo", "hello-from-sandbox"])
        assert out["exit_code"] == 0
        assert "hello-from-sandbox" in out["stdout"]
        assert out.get("sandboxed") is True
        assert out.get("sandbox_profile") == "default"
