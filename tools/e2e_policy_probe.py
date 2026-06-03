"""Quick policy-layer probe for the three e2e scenarios."""
import json
import shlex

from sift_mcp.policy.evaluator import evaluate_command

CASE = "/cases/e2e-test"
cmds = [
    ("ALLOW?", f"vol -s {CASE}/symbols -f {CASE}/evidence/win7-mem.raw windows.pslist"),
    ("DENY?", f"find {CASE}/evidence -exec rm {{}} ;"),
    ("ALLOW (kernel should block)?", f"touch {CASE}/evidence/proof"),
]
for label, c in cmds:
    d = evaluate_command(shlex.split(c))
    print(f"\n### {label}")
    print(f"  cmd:   {c}")
    print(f"  decision: {json.dumps(d, default=str)}")
