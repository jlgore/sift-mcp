"""Tier-1/2 bwrap sandbox compatibility audit (Phase 1).

For each tool: run BARE (baseline) then SANDBOXED through the real
build_sandbox_prefix()+build_input_doc() path with the default profile.
Classify PASS/DEGRADED/FAIL-SILENT/FAIL-LOUD, categorize the failure, and
emit a YAML compatibility matrix + a summary table.

The point is to surface what each tool tries to write/access that the default
sandbox blocks -- especially the dotnet/Zimmerman $HOME/.dotnet writes that
drive the --setenv implementation. Run ON the SIFT VM:

    cd ~/sift-mcp && .venv/bin/python tools/bwrap_audit.py
"""

from __future__ import annotations

import shlex
import subprocess
import time
from pathlib import Path

import yaml

from sift_mcp.policy.parser import build_input_doc
from sift_mcp.sandbox.bwrap import build_sandbox_prefix, load_profile

CASE = "/cases/e2e-test"
EV = f"{CASE}/evidence"
EX = f"{EV}/extracted"
OUT = f"{CASE}/out"
E01 = f"{EV}/win7-64-nfury-c-drive.E01"
MEM = f"{EV}/win7-mem.raw"
BWRAP = "/usr/bin/bwrap"
TIMEOUT = 180

prof = load_profile("default")
Path(OUT).mkdir(parents=True, exist_ok=True)
_TMP = Path(OUT) / "_audit_stdout.tmp"

# (name, tier, command, note). $MFT is a literal filename; shlex keeps it literal.
TOOLS: list[tuple[str, int, str, str]] = [
    # --- Tier 1: vol3 (memory) ---
    ("vol3.pslist", 1, f"vol -s {CASE}/symbols -f {MEM} windows.pslist", "memory; symbols pre-staged"),
    # --- Tier 1: Sleuth Kit (disk image, read-only by nature) ---
    ("fls", 1, f"fls -r {E01}", "recursive MFT walk"),
    ("fsstat", 1, f"fsstat {E01}", "fs metadata"),
    ("mmls", 1, f"mmls {E01}", "EXPECT baseline-fail: logical image has no partition table"),
    ("icat", 1, f"icat {E01} 0", "extract $MFT to stdout"),
    ("istat", 1, f"istat {E01} 0", "$MFT metadata"),
    ("img_stat", 1, f"img_stat {E01}", "image format info (ewf)"),
    # --- Tier 1: dotnet / Zimmerman (the --setenv headliners) ---
    ("MFTECmd", 1, f"MFTECmd -f {EX}/$MFT --csv {OUT} --csvf mft.csv", "dotnet; writes $HOME/.dotnet"),
    ("EvtxECmd", 1, f"EvtxECmd -f {EX}/Security.evtx --csv {OUT} --csvf sec.csv", "dotnet"),
    ("AppCompatCacheParser", 1, f"AppCompatCacheParser -f {EX}/SYSTEM --csv {OUT} --csvf shim.csv", "dotnet; ShimCache"),
    ("bstrings", 1, f"bstrings -f {EX}/NTUSER.DAT", "dotnet; strings"),
    # --- Tier 1: carving ---
    ("foremost", 1, f"foremost -o {OUT}/foremost-out -i {EX}/Security.evtx", "writes carve output dir"),
    # --- Tier 2: text / inspection / hashing ---
    ("strings", 2, f"strings {EX}/$MFT", "large stdout"),
    ("grep", 2, f"grep -a -c MZ {EX}/$MFT", "count"),
    ("file", 2, f"file {E01}", "magic"),
    ("stat", 2, f"stat {MEM}", "metadata"),
    ("md5sum", 2, f"md5sum {EX}/SYSTEM", "hash"),
    ("sha256sum", 2, f"sha256sum {EX}/SYSTEM", "hash"),
    ("xxd", 2, f"xxd {EX}/Security.evtx", "hexdump"),
    ("readelf", 2, "readelf -h /usr/bin/fls", "elf header of a host binary"),
    ("exiftool", 2, f"exiftool {EX}/Security.evtx", "perl; metadata"),
    ("ssdeep", 2, f"ssdeep {EX}/SYSTEM", "fuzzy hash"),
    # --- Tier 3 ---
    ("bulk_extractor", 3, f"bulk_extractor -o {OUT}/be-out -E email {EX}/$MFT", "writes output dir"),
]


def _clean_output_dir(argv: list[str]) -> None:
    """Carve tools (foremost, bulk_extractor) refuse a pre-existing -o dir and
    'resume' instead. The bare run would populate it and make the sandboxed run
    trip, so wipe a dedicated -o subdir of OUT before EACH run."""
    if "-o" in argv:
        d = argv[argv.index("-o") + 1]
        if d.startswith(OUT) and Path(d).resolve() != Path(OUT).resolve():
            subprocess.run(["rm", "-rf", d], check=False)


def _run(argv: list[str], cwd: str) -> dict:
    """Run argv, stream stdout to a temp file (measure bytes), capture stderr."""
    _clean_output_dir(argv)
    start = time.monotonic()
    try:
        with open(_TMP, "wb") as fh:
            proc = subprocess.run(
                argv, cwd=cwd, stdout=fh, stderr=subprocess.PIPE, timeout=TIMEOUT
            )
        return {
            "rc": proc.returncode,
            "out_bytes": _TMP.stat().st_size,
            "stderr": proc.stderr.decode("utf-8", "replace")[:1500],
            "elapsed": round(time.monotonic() - start, 2),
            "timeout": False,
        }
    except subprocess.TimeoutExpired:
        return {"rc": -1, "out_bytes": 0, "stderr": "TIMEOUT", "elapsed": TIMEOUT, "timeout": True}
    except Exception as exc:  # noqa: BLE001
        return {"rc": -1, "out_bytes": 0, "stderr": f"{type(exc).__name__}: {exc}", "elapsed": 0.0, "timeout": False}


def _categorize(stderr: str) -> list[str]:
    s = stderr.lower()
    cats = []
    if "read-only file system" in s or "erofs" in s:
        cats.append("WRITE-RO")
    if ".dotnet" in s or "dotnet_cli" in s or "coreclr" in s or "/.nuget" in s:
        cats.append("WRITE-HOME-DOTNET")
    if "permission denied" in s and ("home" in s or "/.local" in s or "/.config" in s or "/.cache" in s):
        cats.append("WRITE-HOME")
    if "no such file or directory" in s and ("home" in s or "/.dotnet" in s or "/.config" in s):
        cats.append("MISSING-HOME")
    if "network is unreachable" in s or "name resolution" in s or "could not resolve" in s or "connection refused" in s:
        cats.append("NETWORK")
    if "no such file or directory" in s and "/proc" in s:
        cats.append("PROC")
    return cats or (["UNKNOWN"] if stderr.strip() else [])


def _classify(base: dict, sand: dict) -> str:
    if base["rc"] != 0:
        return "BASELINE-FAIL"  # tool/data issue, not a sandbox regression
    if sand["rc"] != 0 or sand["timeout"]:
        return "FAIL-LOUD"
    b, sa = base["out_bytes"], sand["out_bytes"]
    if b > 0 and sa < max(1, b * 0.5):
        return "FAIL-SILENT"
    if sand["stderr"].strip() and not base["stderr"].strip():
        return "DEGRADED"
    return "PASS"


def main() -> None:
    # Clean carve output dirs so tools that "resume on existing dir" start fresh.
    for d in ("foremost-out", "be-out"):
        subprocess.run(["rm", "-rf", f"{OUT}/{d}"], check=False)
    records = []
    print(f"{'TOOL':<24} {'BASE':>6} {'SAND':>6}  RESULT")
    print("-" * 60)
    for name, tier, cmd, note in TOOLS:
        argv = shlex.split(cmd)
        if not Path(f"/usr/bin/{argv[0]}").exists() and not Path(f"/usr/local/bin/{argv[0]}").exists():
            # rely on PATH; build_input_doc/bwrap handle resolution
            pass
        doc = build_input_doc(argv, context={"case_dir": CASE})
        prefix = build_sandbox_prefix(
            input_paths=doc["paths"],
            output_paths=doc["output_paths"],
            device_paths=doc["device_paths"],
            case_dir=CASE,
            profile=prof,
            bwrap_path=BWRAP,
        )
        base = _run(argv, cwd=CASE)
        sand = _run(prefix + argv, cwd=CASE)
        result = _classify(base, sand)
        cats = _categorize(sand["stderr"]) if result in ("FAIL-LOUD", "FAIL-SILENT", "DEGRADED") else []
        rec = {
            "name": name,
            "tier": tier,
            "command": cmd,
            "note": note,
            "baseline": {"rc": base["rc"], "out_bytes": base["out_bytes"], "elapsed_s": base["elapsed"]},
            "sandboxed": {"rc": sand["rc"], "out_bytes": sand["out_bytes"], "elapsed_s": sand["elapsed"]},
            "result": result,
            "failure_category": cats,
            "sandbox_stderr": sand["stderr"] if result != "PASS" else "",
        }
        records.append(rec)
        print(f"{name:<24} {base['rc']:>6} {sand['rc']:>6}  {result} {','.join(cats)}")

    summary = {}
    for r in records:
        summary[r["result"]] = summary.get(r["result"], 0) + 1
    out_yaml = {"profile": "default", "case": CASE, "summary": summary, "tools": records}
    dest = Path(OUT) / "bwrap_audit.yaml"
    dest.write_text(yaml.safe_dump(out_yaml, sort_keys=False, width=100))
    if _TMP.exists():
        _TMP.unlink()
    print("-" * 60)
    print("SUMMARY:", summary)
    print("written:", dest)


if __name__ == "__main__":
    main()
