"""Probe Layer-2 behavior for scenario-3 candidates: which write EROFSes?"""
import shlex
import subprocess

from sift_mcp.policy.parser import build_input_doc
from sift_mcp.sandbox.bwrap import build_sandbox_prefix, load_profile

CASE = "/cases/e2e-test"
prof = load_profile("default")

candidates = [
    f"touch {CASE}/evidence/proof",              # new file in evidence dir
    f"touch {CASE}/evidence/win7-mem.raw",       # existing RO-bound image
]
for c in candidates:
    doc = build_input_doc(shlex.split(c), context={"case_dir": CASE})
    prefix = build_sandbox_prefix(
        input_paths=doc["paths"],
        output_paths=doc["output_paths"],
        device_paths=doc["device_paths"],
        case_dir=CASE,
        profile=prof,
        bwrap_path="/usr/bin/bwrap",
    )
    r = subprocess.run(prefix + shlex.split(c), capture_output=True, text=True)
    print(f"\n### {c}")
    print(f"  doc.paths        = {doc['paths']}")
    print(f"  doc.output_paths = {doc['output_paths']}")
    ro = "win7-mem.raw" in " ".join(prefix) and "--ro-bind" in prefix
    print(f"  evidence-img RO-bound in prefix: {'win7-mem.raw' in ' '.join(prefix)}")
    print(f"  rc = {r.returncode}")
    print(f"  stderr = {r.stderr.strip()[:200]}")
