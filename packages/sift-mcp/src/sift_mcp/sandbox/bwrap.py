"""Build a bubblewrap command prefix from a profile + the paths a tool touches.

The prefix is everything up to and including ``--``; the caller (executor)
appends the real command, so the tool runs as bwrap's child:

    [bwrap, <binds/namespaces>, --] + [/usr/bin/tool, arg, ...]

Design choices that differ from a naive remap-to-/evidence scheme:

* Identity binds — evidence and output are bound at their REAL host paths, so
  the tool's own arguments (which reference real paths) work unchanged. No
  command rewriting.
* Mount ordering — read-write binds (case dir, output parents) are applied
  BEFORE read-only evidence binds, so a piece of evidence nested under a
  writable case directory still ends up read-only (later bind wins in bwrap).
  This is what makes the kernel write-block hold for evidence inside the case.
* Existence-checked — a profile path that doesn't exist (e.g. /opt on a WSL dev
  box) is silently skipped, so one profile works across SIFT and dev machines.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from sift_mcp.exceptions import SandboxError

_PROFILES_DIR = Path(__file__).parent / "profiles"


def verify_bwrap(bwrap_path: str = "") -> str:
    """Return a usable bwrap path or raise SandboxError."""
    candidate = bwrap_path or "bwrap"
    resolved = candidate if Path(candidate).is_absolute() else shutil.which(candidate)
    if not resolved or not Path(resolved).exists():
        raise SandboxError(
            "bubblewrap (bwrap) not found. Install with: "
            "sudo apt-get install -y bubblewrap"
        )
    return resolved


def load_profile(name: str = "default") -> dict:
    """Load a sandbox profile YAML by name from the profiles directory."""
    path = _PROFILES_DIR / f"{name}.yaml"
    try:
        return yaml.safe_load(path.read_text()) or {}
    except OSError as exc:
        raise SandboxError(f"Sandbox profile '{name}' not found at {path}") from exc


def _dedupe_existing(paths: list[str]) -> list[str]:
    """Resolve, dedupe (preserving order), and drop non-existent paths."""
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if not p:
            continue
        rp = str(Path(p).resolve())
        if rp in seen or not Path(rp).exists():
            continue
        seen.add(rp)
        out.append(rp)
    return out


def build_sandbox_prefix(
    *,
    input_paths: list[str] | None = None,
    output_paths: list[str] | None = None,
    device_paths: list[str] | None = None,
    case_dir: str | None = None,
    profile: dict | None = None,
    bwrap_path: str = "",
) -> list[str]:
    """Construct the bwrap command prefix (ending in ``--``).

    Args:
        input_paths: Evidence/input paths -> read-only binds.
        output_paths: Tool output paths -> their parent dirs become read-write.
        device_paths: /dev specifiers (disk forensics) -> dev-bind (best effort).
        case_dir: Active case directory -> read-write bind.
        profile: Pre-loaded profile dict (defaults to the "default" profile).
        bwrap_path: Override the bwrap binary location.
    """
    prof = profile if profile is not None else load_profile("default")
    bwrap = verify_bwrap(bwrap_path)
    cmd: list[str] = [bwrap]

    # 1. Base system/tool read-only binds (identity, existence-checked).
    for p in prof.get("read_only", []):
        if Path(p).exists():
            cmd += ["--ro-bind", p, p]

    # 2. Read-write binds FIRST (so nested evidence RO in step 3 wins).
    if prof.get("bind_tmp_rw", True):
        cmd += ["--bind", "/tmp", "/tmp"]
    else:
        cmd += ["--tmpfs", "/tmp"]

    for out in _dedupe_existing(
        [str(Path(p).parent) for p in (output_paths or []) if p]
    ):
        cmd += ["--bind", out, out]

    if case_dir and Path(case_dir).exists():
        cd = str(Path(case_dir).resolve())
        cmd += ["--bind", cd, cd]

        # 2b. Keep original evidence immutable even though the case dir is RW.
        # The case dir is bound RW so tools can write outputs (out/, symbols/,
        # audit/), but the evidence store must stay read-only at the kernel
        # level — otherwise an agent (or a compromised tool) could CREATE or
        # delete files in evidence/, not just modify referenced files.
        # Order matters (bwrap: later bind wins): RO evidence subdirs first,
        # then RW carve-outs (e.g. evidence/extracted for derived artifacts).
        for sub in prof.get("case_readonly_subdirs", []):
            sp = Path(cd) / sub
            if sp.exists():
                cmd += ["--ro-bind", str(sp), str(sp)]
        for sub in prof.get("case_readwrite_subdirs", []):
            sp = Path(cd) / sub
            if sp.exists():
                cmd += ["--bind", str(sp), str(sp)]

    # 3. Evidence/input read-only binds LAST — override any RW parent above.
    for p in _dedupe_existing(input_paths or []):
        cmd += ["--ro-bind", p, p]

    # 4. Device specifiers for disk forensics (best effort; node may be absent).
    for p in device_paths or []:
        cmd += ["--dev-bind-try", p, p]

    # 5. Special filesystems.
    if prof.get("proc"):
        cmd += ["--proc", "/proc"]
    if prof.get("dev") == "minimal":
        cmd += ["--dev", "/dev"]

    # 6. Namespace isolation + process safety.
    for ns in prof.get("unshare", []):
        cmd.append(f"--unshare-{ns}")
    if prof.get("die_with_parent"):
        cmd.append("--die-with-parent")
    if prof.get("new_session"):
        cmd.append("--new-session")

    # 7. Deterministic environment (additive --setenv; the inherited env is left
    # otherwise intact). Sorted for stable, testable output. The real-evidence
    # tool audit found no installed tool *requires* this, so the default profile
    # uses it only for hygiene (e.g. dotnet telemetry opt-out, a bound TMPDIR);
    # it's the hook for hardening untrusted-case profiles.
    for key, val in sorted(prof.get("env", {}).items()):
        cmd += ["--setenv", str(key), str(val)]

    cmd.append("--")
    return cmd
