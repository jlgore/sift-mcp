"""Parity harness: prove OPA decisions match security.py decisions.

Two oracles, same command, compare the boolean allow/deny:

* security.py:  ``validate_command()`` raises on deny (the production gauntlet,
  minus binary resolution / execution).
* OPA:          ``evaluate_command()`` returns allowed + reasons.

Parity is measured against security.py's ACTUAL behavior (quirks included), not
the YAML's intent — the bar for "OPA can replace security.py without behavior
change". Run as a report:

    python -m sift_mcp.policy.parity --fuzz 3000 --out docs/parity-report.md

Both oracles read ambient context (active case dir via VHIR_CASE_DIR, cwd) at
call time, so the caller sets that context before running a batch.
"""

from __future__ import annotations

import json
import os
import random
from dataclasses import dataclass, field
from pathlib import Path

from sift_mcp.exceptions import SiftError
from sift_mcp.policy.evaluator import evaluate_command
from sift_mcp.security import validate_command


@dataclass
class Case:
    command: list[str]
    category: str
    note: str = ""
    requires_case: bool = False  # needs an active case dir to be meaningful


@dataclass
class Result:
    command: list[str]
    category: str
    secpy_denied: bool
    opa_denied: bool
    secpy_error: str
    opa_reasons: list[str] = field(default_factory=list)

    @property
    def parity(self) -> bool:
        return self.secpy_denied == self.opa_denied


# --- Oracles ---------------------------------------------------------------


def secpy_decision(command: list[str]) -> tuple[bool, str]:
    """(denied, error_message) per the security.py gauntlet."""
    try:
        validate_command(command)
        return False, ""
    except (SiftError, ValueError) as exc:
        return True, str(exc)


def opa_decision(command: list[str]) -> tuple[bool, list[str]]:
    """(denied, reasons) per OPA."""
    decision = evaluate_command(command)
    return (not decision.get("allowed", False)), decision.get("reasons", [])


def compare(case: Case) -> Result:
    sd, se = secpy_decision(case.command)
    od, reasons = opa_decision(case.command)
    return Result(case.command, case.category, sd, od, se, reasons)


# --- Curated corpus --------------------------------------------------------

_VHIR = os.path.expanduser("~/.vhir")

CURATED: list[Case] = [
    # denied binaries (+ near-misses that must stay allowed)
    Case(["mkfs", "/dev/sda1"], "denied_binary"),
    Case(["mkfs.ext4", "/dev/sda1"], "denied_binary"),
    Case(["/usr/sbin/mkfs", "/dev/sda1"], "denied_binary", "path-prefixed"),
    Case(["SHUTDOWN", "-h", "now"], "denied_binary", "case-insensitive"),
    Case(["kill", "-9", "1234"], "denied_binary"),
    Case(["nc", "-l", "4444"], "denied_binary"),
    Case(["env"], "denied_binary"),
    Case(["dd", "if=/cases/c/disk.img", "of=/tmp/out.img"], "denied_binary", "dd allowed"),
    Case(["fdisk", "-l"], "denied_binary", "fdisk allowed"),
    Case(["mount"], "denied_binary", "mount allowed"),
    Case(["strings", "/cases/c/file.bin"], "denied_binary", "allowed"),
    # per-tool blocked flags
    Case(["find", "/cases", "-name", "*.log", "-exec", "rm", "{}", "+"], "tool_blocked_flags"),
    Case(["find", "/cases", "-execdir", "cat", "{}", ";"], "tool_blocked_flags"),
    Case(["find", "/cases", "-name", "*.tmp", "-delete"], "tool_blocked_flags"),
    Case(["find", "/cases", "-fls", "/tmp/o"], "tool_blocked_flags"),
    Case(["find", "/cases", "-fprintf", "/tmp/o", "%p"], "tool_blocked_flags"),
    Case(["sed", "-i", "s/a/b/", "/cases/c/f.txt"], "tool_blocked_flags"),
    Case(["sed", "--in-place", "s/a/b/", "/cases/c/f.txt"], "tool_blocked_flags"),
    Case(["tar", "-x", "-f", "/cases/c/a.tar"], "tool_blocked_flags"),
    Case(["tar", "--delete", "-f", "/cases/c/a.tar"], "tool_blocked_flags"),
    Case(["unzip", "-o", "/cases/c/a.zip"], "tool_blocked_flags"),
    Case(["find", "/cases", "-name", "*.evtx", "-type", "f"], "tool_blocked_flags", "allowed"),
    Case(["sed", "s/a/b/", "/cases/c/f.txt"], "tool_blocked_flags", "read-only allowed"),
    Case(["tar", "-t", "-f", "/cases/c/a.tar"], "tool_blocked_flags", "list allowed"),
    # global dangerous flags (+ exception that is dead in the live path)
    Case(["sometool", "-e", "payload"], "dangerous_flags"),
    Case(["sometool", "--exec", "x"], "dangerous_flags"),
    Case(["sometool", "--command", "x"], "dangerous_flags"),
    Case(["pwsh", "-enc", "AAAA"], "dangerous_flags"),
    Case(["sometool", "--script", "x"], "dangerous_flags"),
    Case(["bulk_extractor", "-e", "email", "-o", "/tmp/o"], "dangerous_flags", "dead exception → both deny"),
    Case(["grep", "-r", "pattern", "/cases/c"], "dangerous_flags", "benign allowed"),
    # shell metacharacters
    Case(["sometool", "--flag; rm -rf /"], "shell_metacharacters"),
    Case(["sometool", "$(whoami)"], "shell_metacharacters"),
    Case(["sometool", "a&&b"], "shell_metacharacters"),
    Case(["sometool", "a||b"], "shell_metacharacters"),
    Case(["sometool", "`id`"], "shell_metacharacters"),
    Case(["sometool", "${HOME}"], "shell_metacharacters"),
    Case(["grep", "foo", "/cases/c/f"], "shell_metacharacters", "clean allowed"),
    # awk program text
    Case(["awk", '{system("id")}', "/cases/c/f"], "awk_scanning"),
    Case(["gawk", "/x/{getline}", "/cases/c/f"], "awk_scanning"),
    Case(["awk", '{print > "/tmp/x"}', "/cases/c/f"], "awk_scanning", "redirect"),
    Case(["awk", '{print $1 | "sort"}', "/cases/c/f"], "awk_scanning", "pipe"),
    Case(["awk", "{print $1}", "/cases/c/f"], "awk_scanning", "benign allowed"),
    Case(["awk", "BEGIN{x=1}", "/cases/c/f"], "awk_scanning", "benign allowed"),
    # input path validation
    Case(["strings", "/etc/shadow"], "input_path"),
    Case(["cat", "/proc/1/cmdline"], "input_path"),
    Case(["cat", "/sys/class/net"], "input_path"),
    Case(["strings", "/dev/sda"], "input_path", "non-dev tool → blocked"),
    Case(["cat", "/boot/vmlinuz"], "input_path"),
    Case(["cat", f"{_VHIR}/config"], "input_path", "~/.vhir blocked"),
    Case(["cat", f"{_VHIR}/cases/c/f"], "input_path", "~/.vhir/cases exception → allowed"),
    Case(["cat", f"{_VHIR}/hayabusa-output/r.json"], "input_path", "exception → allowed"),
    Case(["strings", "/cases/c/image.E01"], "input_path", "allowed"),
    Case(["strings", "/opt/tools/x"], "input_path", "allowed"),
    Case(["strings", "/home/u/evidence/d.dd"], "input_path", "allowed"),
    Case(["strings", "/var/log/syslog"], "input_path", "allowed"),
    Case(["strings", "/usr/bin/ls"], "input_path", "allowed"),
    # /dev device tools
    Case(["fls", "/dev/sda1"], "dev_tool", "allowed"),
    Case(["mmls", "/dev/nvme0n1"], "dev_tool", "allowed"),
    Case(["icat", "/dev/sda1", "5"], "dev_tool", "allowed"),
    # flag=value forms
    Case(["tool", "--input=/etc/shadow"], "flag_value"),
    Case(["tool", "--input=/cases/c/e.img"], "flag_value", "allowed"),
    Case(["tool", "--output=/etc/passwd"], "flag_value", "output blocked"),
    Case(["tool", "--csv=/tmp/o.csv"], "flag_value", "output to /tmp allowed"),
    # output path (no active case)
    Case(["tool", "-o", "/etc/passwd"], "output_path"),
    Case(["tool", "-o", "/usr/local/bin/x"], "output_path"),
    Case(["tool", "--csv", "/var/spool/x"], "output_path"),
    Case(["tool", "-o", "/opt/sneaky/o.csv"], "output_path", "no case → blocked"),
    Case(["tool", "-o", "/tmp/o.csv"], "output_path", "/tmp allowed"),
    # rm protection (static dirs)
    Case(["rm", "-rf", "/cases"], "rm_protection"),
    Case(["rm", "/cases/c/file.txt"], "rm_protection"),
    Case(["rm", "/evidence/disk.dd"], "rm_protection"),
    Case(["rm", "-rf", "/"], "rm_protection", "root"),
    Case(["rm", "/tmp/output.csv"], "rm_protection", "/tmp allowed"),
    Case(["rm", "-f", "/opt/work/temp.txt"], "rm_protection", "allowed"),
    # output path (active case) — require_case scenarios
    Case(["tool", "-o", "OUTPUT_INSIDE"], "output_path_case", "inside case → allowed", requires_case=True),
    Case(["tool", "-o", "/tmp/out.csv"], "output_path_case", "outside case → blocked", requires_case=True),
    Case(["rm", "RM_INSIDE_CASE"], "rm_case", "rm in case dir → blocked", requires_case=True),
]


# --- Fuzzer ----------------------------------------------------------------

_FUZZ_BINARIES = [
    "mkfs", "shutdown", "kill", "nc", "env", "pkill", "reboot",  # denied
    "find", "sed", "tar", "unzip",  # per-tool blocked flags
    "awk", "gawk", "mawk",  # program text
    "fls", "mmls", "dd", "icat", "fsstat",  # dev tools
    "strings", "grep", "cat", "file", "foremost", "bulk_extractor", "vol",  # generic
    "rm",
]
_FUZZ_FLAGS = [
    "-exec", "-execdir", "-delete", "-i", "--in-place", "-x", "-c", "-o", "-n",
    "-e", "--exec", "--command", "-enc", "--script", "--invoke",
    "--csv", "--json", "--output",
    "-r", "-v", "-l", "-a", "--recursive", "-name", "-type", "-h",
]
_FUZZ_PATHS = [
    "/etc/shadow", "/proc/1/status", "/sys/class/x", "/dev/sda", "/boot/x",
    "/cases/c/e.img", "/opt/t/x", "/home/u/d.dd", "/tmp/o.csv", "/var/log/s",
    "/usr/bin/x", "/dev/sda1", "/dev/nvme0n1",
    os.path.expanduser("~/.vhir/x"), os.path.expanduser("~/.vhir/cases/c/f"),
    "out.txt", "../x", "report.bin",
    "/tmp/x;rm -rf /", "$(id)", "a&&b", "`whoami`",
]
_FUZZ_AWK = [
    '{system("id")}', "/x/{getline}", '{print > "/tmp/x"}',
    '{print | "sh"}', "{print $1}", "BEGIN{n=0}",
]


def build_fuzz_cases(n: int, seed: int) -> list[Case]:
    rng = random.Random(seed)
    cases: list[Case] = []
    for _ in range(n):
        binary = rng.choice(_FUZZ_BINARIES)
        args: list[str] = []
        for _ in range(rng.randint(1, 4)):
            roll = rng.random()
            if roll < 0.4:
                args.append(rng.choice(_FUZZ_PATHS))
            elif roll < 0.7:
                args.append(rng.choice(_FUZZ_FLAGS))
            elif roll < 0.85:
                args.append(f"{rng.choice(_FUZZ_FLAGS)}={rng.choice(_FUZZ_PATHS)}")
            else:
                args.append(rng.choice(["value", "pattern", "8", "f", "*.log"]))
        if binary in {"awk", "gawk", "mawk"}:
            args.append(rng.choice(_FUZZ_AWK))
        cases.append(Case([binary, *args], "fuzz"))
    return cases


# --- Running + reporting ---------------------------------------------------


def run_cases(cases: list[Case], active_case_dir: str = "") -> list[Result]:
    """Run a batch under a fixed context. If active_case_dir is set, it is
    exported as VHIR_CASE_DIR and the OUTPUT_INSIDE / RM_INSIDE_CASE placeholders
    are rewritten to a real path inside it."""
    prev = os.environ.get("VHIR_CASE_DIR")
    if active_case_dir:
        os.environ["VHIR_CASE_DIR"] = active_case_dir
    else:
        os.environ.pop("VHIR_CASE_DIR", None)
    try:
        results = []
        for case in cases:
            cmd = [
                str(Path(active_case_dir) / "out" / "o.csv")
                if tok == "OUTPUT_INSIDE"
                else str(Path(active_case_dir) / "f.txt")
                if tok == "RM_INSIDE_CASE"
                else tok
                for tok in case.command
            ]
            results.append(compare(Case(cmd, case.category, case.note)))
        return results
    finally:
        if prev is not None:
            os.environ["VHIR_CASE_DIR"] = prev
        else:
            os.environ.pop("VHIR_CASE_DIR", None)


def summarize(results: list[Result]) -> dict:
    by_cat: dict[str, dict[str, int]] = {}
    for r in results:
        c = by_cat.setdefault(r.category, {"total": 0, "parity": 0})
        c["total"] += 1
        c["parity"] += int(r.parity)
    total = len(results)
    agree = sum(int(r.parity) for r in results)
    return {
        "total": total,
        "parity": agree,
        "divergent": total - agree,
        "rate": (agree / total) if total else 1.0,
        "by_category": by_cat,
    }


def render_markdown(results: list[Result], stats: dict) -> str:
    lines = [
        "# OPA ↔ security.py Parity Report",
        "",
        f"**{stats['parity']}/{stats['total']} cases agree "
        f"({stats['rate'] * 100:.2f}%)** — {stats['divergent']} divergent.",
        "",
        "| Category | Total | Parity | Rate |",
        "|---|---|---|---|",
    ]
    for cat, c in sorted(stats["by_category"].items()):
        lines.append(
            f"| {cat} | {c['total']} | {c['parity']} | "
            f"{c['parity'] / c['total'] * 100:.0f}% |"
        )
    divergences = [r for r in results if not r.parity]
    if divergences:
        lines += ["", "## Divergences", ""]
        for r in divergences:
            lines.append(
                f"- `{' '.join(r.command)}` — security.py "
                f"{'DENY' if r.secpy_denied else 'ALLOW'} vs OPA "
                f"{'DENY' if r.opa_denied else 'ALLOW'}"
            )
            if r.secpy_denied:
                lines.append(f"  - security.py: {r.secpy_error}")
            if r.opa_denied:
                lines.append(f"  - OPA: {'; '.join(r.opa_reasons)}")
    else:
        lines += ["", "No divergences. ✅"]
    return "\n".join(lines) + "\n"


def _main(argv: list[str] | None = None) -> int:
    import argparse
    import tempfile

    p = argparse.ArgumentParser(prog="sift_mcp.policy.parity")
    p.add_argument("--fuzz", type=int, default=2000, help="number of fuzz cases")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--out", default="", help="write markdown report to this path")
    p.add_argument("--json", default="", help="write JSON results to this path")
    args = p.parse_args(argv)

    no_case = [c for c in CURATED if not c.requires_case]
    with_case = [c for c in CURATED if c.requires_case]

    results = run_cases(no_case + build_fuzz_cases(args.fuzz, args.seed))

    if with_case:
        case_dir = Path(tempfile.mkdtemp(prefix="parity-case-"))
        (case_dir / "CASE.yaml").write_text("case_id: parity\n")
        (case_dir / "out").mkdir(exist_ok=True)
        results += run_cases(with_case, active_case_dir=str(case_dir))

    stats = summarize(results)
    md = render_markdown(results, stats)

    if args.out:
        Path(args.out).write_text(md)
    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "stats": stats,
                    "divergences": [
                        {
                            "command": r.command,
                            "category": r.category,
                            "secpy_denied": r.secpy_denied,
                            "opa_denied": r.opa_denied,
                            "secpy_error": r.secpy_error,
                            "opa_reasons": r.opa_reasons,
                        }
                        for r in results
                        if not r.parity
                    ],
                },
                indent=2,
            )
        )

    print(
        f"Parity: {stats['parity']}/{stats['total']} "
        f"({stats['rate'] * 100:.2f}%), {stats['divergent']} divergent."
    )
    return 0 if stats["divergent"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(_main())
