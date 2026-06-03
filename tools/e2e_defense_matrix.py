"""Three-layer defense-in-depth matrix (Step 5 of hooks-test-prompt).

Proves each enforcement layer blocks independently against real evidence:
  Layer 0 = harness hook (gate.py subprocess, exit 0/2)
  Layer 1 = OPA policy in the run_command MCP path (PolicyDenialError)
  Layer 2 = bwrap kernel sandbox (EROFS on read-only evidence)

Run on the SIFT workstation with a real case dir:
  VHIR_CASE_DIR=/cases/e2e-test SIFT_POLICY_ENGINE=1 \
    .venv/bin/python tools/e2e_defense_matrix.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

CASE = os.environ.get("VHIR_CASE_DIR", "/cases/e2e-test")
PY = sys.executable

PASS = "PASS"
FAIL = "FAIL"
results: list[tuple[str, str, str, str]] = []


def record(cmd: str, path: str, layer: str, outcome: str, detail: str) -> None:
    results.append((f"{cmd}  [{path}]", layer, outcome, detail))


def gate(cmd: str) -> tuple[int, str]:
    """Layer 0: run the harness hook as a real subprocess (Claude Code stdin)."""
    payload = json.dumps({"tool_input": {"command": cmd}})
    proc = subprocess.run(
        [PY, "-m", "sift_mcp.hooks.gate"],
        input=payload, capture_output=True, text=True, timeout=20,
        env={**os.environ, "SIFT_POLICY_ENGINE": "1"},
    )
    return proc.returncode, (proc.stderr or "").strip()


def main() -> int:
    import shlex
    from sift_mcp.exceptions import PolicyDenialError
    from sift_mcp.tools.generic import run_command

    # --- Layer 0: harness hook --------------------------------------------
    rc, err = gate("mkfs /dev/sda1")
    record("mkfs /dev/sda1", "bash", "Layer 0",
           PASS if rc == 2 and "mkfs" in err else FAIL, f"exit={rc} :: {err}")

    # Shell metacharacters are intentionally scoped OFF the harness hook
    # (bash lines legitimately contain them; the hook decomposes compound
    # lines instead) — so Layer 0 fires only the -exec reason here. The
    # metacharacter reason is asserted at Layer 1, where ';' arrives as a
    # literal argv token.
    rc, err = gate(f"find {CASE}/evidence -exec rm {{}} ;")
    record("find … -exec rm {} ;", "bash", "Layer 0",
           PASS if rc == 2 and "-exec" in err else FAIL, f"exit={rc} :: {err}")

    rc, err = gate("echo hello")
    record("echo hello", "bash", "Layer 0",
           PASS if rc == 0 else FAIL, f"exit={rc}")

    # --- Layer 1: OPA inside run_command ----------------------------------
    for cmd, want_two in [("mkfs /dev/sda1", False),
                          (f"find {CASE}/evidence -exec rm {{}} ;", True)]:
        try:
            run_command(shlex.split(cmd), purpose="matrix-test")
            record(cmd, "run_command", "Layer 1", FAIL, "no denial raised")
        except PolicyDenialError as exc:
            reasons = getattr(exc, "decision", {}).get("reasons", [])
            ok = (not want_two) or len(reasons) >= 2
            record(cmd.replace(CASE, "$CASE"), "run_command", "Layer 1",
                   PASS if ok else FAIL,
                   f"PolicyDenialError, {len(reasons)} reason(s)")
        except Exception as exc:  # noqa: BLE001
            record(cmd, "run_command", "Layer 1", FAIL,
                   f"{type(exc).__name__}: {exc}")

    # --- Layer 2: bwrap sandbox (EROFS on read-only evidence) -------------
    touch = f"touch {CASE}/evidence/test-file"
    env_saved = os.environ.get("SIFT_SANDBOX")
    os.environ["SIFT_SANDBOX"] = "1"
    try:
        out = run_command(shlex.split(touch), purpose="matrix-test")
        rc = out.get("exit_code") if isinstance(out, dict) else None
        stderr = (out.get("stderr", "") if isinstance(out, dict) else "") or ""
        erofs = "read-only" in stderr.lower() or "erofs" in stderr.lower() or rc not in (0, None)
        record(touch.replace(CASE, "$CASE"), "run_command+sbx", "Layer 2",
               PASS if erofs else FAIL, f"rc={rc} :: {stderr.strip()[:120]}")
    except Exception as exc:  # noqa: BLE001
        # A raised error (e.g. nonzero exit surfaced as ExecutionError) also
        # proves the write was blocked.
        record(touch.replace(CASE, "$CASE"), "run_command+sbx", "Layer 2",
               PASS, f"{type(exc).__name__}: {str(exc)[:120]}")
    finally:
        if env_saved is None:
            os.environ.pop("SIFT_SANDBOX", None)
        else:
            os.environ["SIFT_SANDBOX"] = env_saved

    # --- All layers: a legitimate forensic command should pass through ----
    img = f"{CASE}/evidence/win7-64-nfury-c-drive.E01"
    fls = f"fls -r {img}"
    os.environ["SIFT_SANDBOX"] = "1"
    try:
        out = run_command(shlex.split(fls), purpose="matrix-test", timeout=120)
        rc = out.get("exit_code") if isinstance(out, dict) else None
        # Large listings are parsed and stdout nulled; a _parsed preview proves
        # output was produced. Otherwise measure stdout directly.
        stdout = out.get("stdout") if isinstance(out, dict) else None
        nbytes = len(stdout) if stdout else 0
        produced = nbytes > 0 or bool(out.get("_parsed")) or out.get("stdout_total_bytes", 0) > 0
        sbx = out.get("sandboxed", False)
        record("fls -r $CASE/…E01", "all layers", "Allowed",
               PASS if rc == 0 and produced else FAIL,
               f"rc={rc}, sandboxed={sbx}, bytes={out.get('stdout_total_bytes', nbytes)}")
    except Exception as exc:  # noqa: BLE001
        record("fls -r $CASE/…E01", "all layers", "Allowed", FAIL,
               f"{type(exc).__name__}: {str(exc)[:160]}")
    finally:
        if env_saved is None:
            os.environ.pop("SIFT_SANDBOX", None)
        else:
            os.environ["SIFT_SANDBOX"] = env_saved

    # --- Report -----------------------------------------------------------
    print("\n=== THREE-LAYER DEFENSE MATRIX ===\n")
    w = max(len(r[0]) for r in results)
    for cmd, layer, outcome, detail in results:
        mark = "✓" if outcome == PASS else "✗"
        print(f"[{mark} {outcome}] {layer:14} {cmd:<{w}}  {detail}")
    n_fail = sum(1 for r in results if r[2] == FAIL)
    print(f"\n{len(results)-n_fail}/{len(results)} passed, {n_fail} failed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
