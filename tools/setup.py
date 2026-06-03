#!/usr/bin/env python3
"""Unified setup for SIFT MCP policy enforcement across agent harnesses.

Discovers installed agent harnesses (Claude Code, OpenCode, Pi), presents
an interactive menu, and installs:

  1. MCP server configuration (sift-gateway connection)
  2. Policy gate hook with bwrap sandbox wrapping (Layer 0)
  3. TypeScript plugin/extension (OpenCode, Pi)
  4. Forensic discipline files (AGENTS.md, etc.)

Usage:
    python3 -m sift_mcp.setup                    # interactive
    python3 -m sift_mcp.setup --all               # all detected harnesses
    python3 -m sift_mcp.setup --harness claude-code
    python3 -m sift_mcp.setup --harness opencode
    python3 -m sift_mcp.setup --harness pi
    python3 -m sift_mcp.setup --list              # just show what's detected
    python3 -m sift_mcp.setup --gateway-url http://192.168.8.129:4508
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import NamedTuple

import yaml


# ───────────────────────────────── constants ──────────────────────────────────

HARNESS_IDS = ("claude-code", "opencode", "pi")

DEFAULT_GATEWAY_URL = "http://127.0.0.1:4508/mcp"

# Path to the sift_mcp package (for locating hook scripts, extensions, etc.)
_SIFT_MCP_PKG = Path(__file__).resolve().parent

# Fallback: if run standalone, look relative to repo root
_REPO_ROOT = _SIFT_MCP_PKG.parents[3] if _SIFT_MCP_PKG.name == "sift_mcp" else Path.cwd()

_AGENTS_MD = _REPO_ROOT / "AGENTS.md"

# Distributable Claude Code subagent definitions (forensic-critic, …).
_SUBAGENTS_SRC = _REPO_ROOT / "claude-code" / "full" / "agents"

# Colors (ANSI)
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _ok(msg: str) -> None:
    print(f"  {_GREEN}✓{_RESET} {msg}")


def _warn(msg: str) -> None:
    print(f"  {_YELLOW}⚠{_RESET} {msg}")


def _err(msg: str) -> None:
    print(f"  {_RED}✗{_RESET} {msg}")


def _info(msg: str) -> None:
    print(f"  {_DIM}→{_RESET} {msg}")


def _header(msg: str) -> None:
    print(f"\n{_BOLD}{_CYAN}{msg}{_RESET}")


# ──────────────────────────── scope helpers ───────────────────────────────────

# Marker used to make the global discipline-file import idempotent.
_MEM_MARKER = "<!-- sift-mcp:forensic-discipline -->"


def _backup_once(path: Path) -> None:
    """Make a one-time .sift-bak copy of an existing config before we edit it.

    Only the first edit creates the backup, so re-running setup never clobbers
    the user's pristine pre-sift state.
    """
    if path.exists():
        bak = path.with_name(path.name + ".sift-bak")
        if not bak.exists():
            shutil.copy2(path, bak)


def _load_json_lenient(path: Path) -> dict:
    """Load a JSON / JSONC config, tolerating comment lines and trailing state.

    OpenCode uses ``opencode.jsonc``; Claude's ``~/.claude.json`` is plain JSON
    but large. Returns ``{}`` for a missing file.
    """
    if not path.exists():
        return {}
    text = path.read_text()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        import re

        # Strip /* block */ comments and whole-line // comments only — never an
        # inline // so we don't corrupt URLs like https://… inside values.
        stripped = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        stripped = re.sub(r"(?m)^\s*//.*$", "", stripped)
        return json.loads(stripped)


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _install_discipline(harness_id: str, project_dir: str, scope: str) -> str:
    """Place the forensic-discipline instructions for the given harness/scope.

    user scope:
      - claude-code → append an ``@AGENTS.md`` import to ~/.claude/CLAUDE.md
        (Claude Code reads CLAUDE.md, not AGENTS.md, globally).
      - opencode    → copy AGENTS.md to ~/.config/opencode/AGENTS.md.
    project scope: copy AGENTS.md into the project root (legacy behaviour).
    """
    home = Path.home()
    if not _AGENTS_MD.exists():
        return "agents: AGENTS.md source not found (skipped)"

    if scope == "project":
        agents_dst = Path(project_dir) / "AGENTS.md"
        if agents_dst.exists():
            return "agents: AGENTS.md already present"
        shutil.copy2(_AGENTS_MD, agents_dst)
        return "agents: copied AGENTS.md"

    # user scope
    if harness_id == "claude-code":
        claude_md = home / ".claude" / "CLAUDE.md"
        existing = claude_md.read_text() if claude_md.exists() else ""
        if _MEM_MARKER in existing:
            return "memory: discipline import already in ~/.claude/CLAUDE.md"
        block = (
            f"\n{_MEM_MARKER}\n"
            f"# SIFT forensic discipline\n"
            f"@{_AGENTS_MD}\n"
        )
        _backup_once(claude_md)
        claude_md.parent.mkdir(parents=True, exist_ok=True)
        claude_md.write_text(existing + block)
        return "memory: appended AGENTS.md import to ~/.claude/CLAUDE.md"

    # opencode (and any other harness that reads AGENTS.md natively)
    agents_dst = home / ".config" / "opencode" / "AGENTS.md"
    if agents_dst.exists():
        return f"agents: AGENTS.md already present ({agents_dst})"
    agents_dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_AGENTS_MD, agents_dst)
    return f"agents: copied AGENTS.md → {agents_dst}"


def _install_subagents(project_dir: str, scope: str) -> list[str]:
    """Deploy Claude Code subagent definitions (e.g. forensic-critic).

    Copies every ``claude-code/full/agents/*.md`` to the Claude Code agents
    directory — ``~/.claude/agents/`` (user scope) or ``<project>/.claude/
    agents/`` (project scope). Subagents are overwritten so updates propagate
    on re-run, mirroring the hook/plugin behaviour.
    """
    results: list[str] = []
    if not _SUBAGENTS_SRC.is_dir():
        return results
    sources = sorted(_SUBAGENTS_SRC.glob("*.md"))
    if not sources:
        return results

    if scope == "user":
        dest_dir = Path.home() / ".claude" / "agents"
    else:
        dest_dir = Path(project_dir) / ".claude" / "agents"
    dest_dir.mkdir(parents=True, exist_ok=True)

    for src in sources:
        dst = dest_dir / src.name
        verb = "updated" if dst.exists() else "installed"
        shutil.copy2(src, dst)
        results.append(f"agent: {verb} {src.stem} → {dst}")
    return results


# ──────────────────────────────── discovery ───────────────────────────────────


class HarnessInfo(NamedTuple):
    id: str
    name: str
    detected: bool
    binary: str | None
    config_dir: str | None
    signals: list[str]


def _which(name: str) -> str | None:
    return shutil.which(name)


def _gate_python() -> str:
    """Resolve an interpreter that can import sift_mcp for the policy gate.

    The gate command is baked into harness configs with an absolute
    interpreter path, so sys.executable is only correct when setup runs from
    an env with sift-mcp installed. Fall back to the repo venv; fail loudly
    rather than installing a hook that errors on every Bash call.
    """
    import subprocess

    candidates = [sys.executable, str(_REPO_ROOT / ".venv" / "bin" / "python")]
    for py in candidates:
        if Path(py).exists() and (
            subprocess.run(
                [py, "-c", "import sift_mcp.hooks.gate"], capture_output=True
            ).returncode
            == 0
        ):
            return py
    raise SystemExit(
        "error: no interpreter can import sift_mcp "
        f"(tried: {', '.join(candidates)}).\n"
        "Run setup with the repo venv python "
        "(.venv/bin/python tools/setup.py …) or install sift-mcp first."
    )


def detect_harness(harness_id: str, project_dir: str) -> HarnessInfo:
    """Detect whether a specific harness is present."""
    p = Path(project_dir)

    if harness_id == "claude-code":
        signals = []
        binary = _which("claude")
        if binary:
            signals.append(f"binary: {binary}")
        if (p / ".claude").is_dir():
            signals.append(f"config: {p / '.claude'}")
        if (p / "CLAUDE.md").exists():
            signals.append(f"file: {p / 'CLAUDE.md'}")
        # Also check global
        global_claude = Path.home() / ".claude"
        if global_claude.is_dir():
            signals.append(f"global: {global_claude}")
        config_dir = str(p / ".claude") if (p / ".claude").is_dir() else None
        return HarnessInfo("claude-code", "Claude Code", bool(signals), binary, config_dir, signals)

    elif harness_id == "opencode":
        signals = []
        binary = _which("opencode")
        if binary:
            signals.append(f"binary: {binary}")
        if (p / ".opencode").is_dir():
            signals.append(f"config: {p / '.opencode'}")
        if (p / "opencode.json").exists():
            signals.append(f"file: {p / 'opencode.json'}")
        global_oc = Path.home() / ".config" / "opencode"
        if global_oc.is_dir():
            signals.append(f"global: {global_oc}")
        config_dir = str(p / ".opencode") if (p / ".opencode").is_dir() else None
        return HarnessInfo("opencode", "OpenCode", bool(signals), binary, config_dir, signals)

    elif harness_id == "pi":
        signals = []
        # Check for both pi and omp (oh-my-pi fork)
        binary = _which("pi") or _which("omp")
        if binary:
            signals.append(f"binary: {binary}")
        if (p / ".pi").is_dir():
            signals.append(f"config: {p / '.pi'}")
        if (p / ".omp").is_dir():
            signals.append(f"config: {p / '.omp'}")
        if list(p.glob("pi.config.*")):
            signals.append("file: pi.config.*")
        config_dir = str(p / ".pi") if (p / ".pi").is_dir() else (
            str(p / ".omp") if (p / ".omp").is_dir() else None
        )
        return HarnessInfo("pi", "Pi / oh-my-pi", bool(signals), binary, config_dir, signals)

    raise ValueError(f"Unknown harness: {harness_id}")


def detect_all(project_dir: str) -> list[HarnessInfo]:
    """Detect all supported harnesses."""
    return [detect_harness(h, project_dir) for h in HARNESS_IDS]


# ──────────────────────────────── prereqs ─────────────────────────────────────


def check_prerequisites() -> dict[str, str | None]:
    """Check for required and optional binaries."""
    checks = {}
    checks["python3"] = _which("python3") or sys.executable
    checks["opa"] = _which("opa") or (
        str(_REPO_ROOT / "tools" / "opa")
        if (_REPO_ROOT / "tools" / "opa").exists()
        else None
    )
    checks["bwrap"] = _which("bwrap")
    return checks


# ─────────────────────────── install: claude code ─────────────────────────────


def install_claude_code(
    project_dir: str,
    gateway_url: str,
    auth_token: str = "",
    scope: str = "user",
    transport: str = "http",
    gateway_config: str = "",
    with_hook: bool = True,
) -> list[str]:
    """Install MCP config + policy gate hook for Claude Code.

    user scope (default) writes global config that applies to every project:
      MCP   → ~/.claude.json   (top-level ``mcpServers`` = user scope)
      hooks → ~/.claude/settings.json
    project scope writes into the project directory (.mcp.json / settings.local.json).

    transport="http"  → connect to a running gateway at ``gateway_url``.
    transport="stdio" → Claude Code spawns the gateway itself on launch via
      ``python -m sift_gateway --stdio`` (no separately-running service).
    """
    results = []
    p = Path(project_dir)
    home = Path.home()

    if scope == "user":
        mcp_path = home / ".claude.json"
        settings_path = home / ".claude" / "settings.json"
    else:
        mcp_path = p / ".mcp.json"
        settings_path = p / ".claude" / "settings.local.json"

    # 1. MCP server config
    _backup_once(mcp_path)
    mcp = _load_json_lenient(mcp_path)
    servers = mcp.setdefault("mcpServers", {})
    if transport == "stdio":
        entry = {
            "command": _gate_python(),
            "args": ["-m", "sift_gateway", "--stdio", "--config", gateway_config],
        }
    else:
        entry = {"type": "streamable-http", "url": gateway_url}
        if auth_token:
            entry["headers"] = {"Authorization": f"Bearer {auth_token}"}

    if "vhir" in servers:
        results.append("mcp: vhir already configured (updated URL)")
    else:
        results.append("mcp: added vhir server")
    servers["vhir"] = entry
    _write_json(mcp_path, mcp)
    results.append(f"mcp: wrote {mcp_path}")

    # 2. Policy gate hook (PreToolUse with updatedInput for bwrap wrapping)
    if not with_hook:
        results.append("hook: skipped (--no-hook)")
    else:
        _backup_once(settings_path)
        settings = _load_json_lenient(settings_path)
        hooks = settings.setdefault("hooks", {})
        pre_tool = hooks.setdefault("PreToolUse", [])

        # Bake the enforcement toggles into the hook command itself so the gate
        # enforces regardless of how the harness was launched. Without these, the
        # gate inherits the agent's ambient environment and silently no-ops when
        # SIFT_POLICY_ENGINE / SIFT_SANDBOX aren't exported (a common footgun).
        opa_path = _which("opa") or str(_REPO_ROOT / "tools" / "opa")
        gate_env = f"SIFT_POLICY_ENGINE=1 SIFT_SANDBOX=1 SIFT_OPA_PATH={opa_path}"
        gate_cmd = f"env {gate_env} {_gate_python()} -m sift_mcp.hooks.gate"

        # Find an existing sift gate hook (match on the module, not the full
        # command, so we can upgrade an older command in place).
        gate_hook = None
        for entry_item in pre_tool:
            for h in entry_item.get("hooks", []):
                if h.get("command", "").rstrip().endswith("sift_mcp.hooks.gate"):
                    gate_hook = h
                    break
            if gate_hook:
                break

        if gate_hook is None:
            pre_tool.append({
                "matcher": "Bash",
                "hooks": [{
                    "type": "command",
                    "command": gate_cmd,
                    "timeout": 10,
                }],
            })
            results.append("hook: installed policy gate (PreToolUse → Bash)")
        elif gate_hook.get("command") != gate_cmd:
            gate_hook["command"] = gate_cmd
            results.append("hook: updated policy gate (enforcement env baked in)")
        else:
            results.append("hook: policy gate already installed")

        _write_json(settings_path, settings)
        results.append(f"hook: wrote {settings_path}")

    # 3. Forensic discipline instructions
    results.append(_install_discipline("claude-code", project_dir, scope))

    # 4. Claude Code subagents (forensic-critic, …)
    results.extend(_install_subagents(project_dir, scope))

    return results


# ─────────────────────────── install: opencode ────────────────────────────────

_OPENCODE_PLUGIN_TEMPLATE = '''\
/**
 * SIFT policy gate + bwrap sandbox plugin for OpenCode.
 *
 * Intercepts bash tool calls, evaluates them against the OPA policy engine,
 * and wraps allowed commands in a bubblewrap sandbox with evidence read-only.
 *
 * Generated by: python3 -m sift_mcp.setup
 */

import {{ execSync }} from "child_process";

export const SiftPolicyGate = async () => ({{
  "tool.execute.before": async (input, output) => {{
    if (input.tool !== "bash") return;
    const cmd = output.args?.command ?? "";
    if (!cmd) return;

    let result;
    try {{
      result = execSync(
        `{python_bin} -m sift_mcp.hooks.gate`,
        {{
          input: JSON.stringify({{ command: cmd }}),
          timeout: 10000,
          stdio: ["pipe", "pipe", "pipe"],
          env: {{ ...process.env }},
        }}
      );
    }} catch (err) {{
      if (err.status === 2) {{
        const reason = err.stderr?.toString().trim() || "denied by sift-mcp policy";
        throw new Error(reason);
      }}
      // Non-2 error or timeout — fail open
      const msg = err.stderr?.toString().trim() || err.message;
      console.warn(`[sift-policy] gate error (fail-open): ${{msg}}`);
      return;
    }}

    // If gate returned JSON on stdout, apply the sandboxed command rewrite
    const stdout = result?.toString().trim();
    if (stdout) {{
      try {{
        const decision = JSON.parse(stdout);
        if (decision.command) {{
          output.args.command = decision.command;
        }}
      }} catch {{
        // Not JSON — gate allowed without modification
      }}
    }}
  }},
}});
'''


def install_opencode(
    project_dir: str,
    gateway_url: str,
    auth_token: str = "",
    scope: str = "user",
    transport: str = "http",
    gateway_config: str = "",
    with_hook: bool = True,
) -> list[str]:
    """Install MCP config + TypeScript plugin for OpenCode.

    user scope (default) writes global config under ~/.config/opencode:
      config → ~/.config/opencode/opencode.jsonc (or opencode.json)
      plugin → ~/.config/opencode/plugins/sift-policy-gate.ts
    project scope writes into ./opencode.json and ./.opencode/plugins/.

    Only ``transport="http"`` is supported here — OpenCode's MCP config uses a
    remote URL; a stdio spawn form isn't wired for it yet.
    """
    results = []
    p = Path(project_dir)
    home = Path.home()
    if transport == "stdio":
        results.append("mcp: stdio transport not supported for OpenCode — using http url")

    if scope == "user":
        cfg_dir = home / ".config" / "opencode"
        plugin_dir = cfg_dir / "plugins"
    else:
        cfg_dir = p
        plugin_dir = p / ".opencode" / "plugins"

    # 1. MCP server config — honour an existing .jsonc, else default to .json
    jsonc = cfg_dir / "opencode.jsonc"
    oc_config_path = jsonc if jsonc.exists() else cfg_dir / "opencode.json"

    _backup_once(oc_config_path)
    oc_config = _load_json_lenient(oc_config_path)
    mcp = oc_config.setdefault("mcp", {})
    entry: dict = {"type": "http", "url": gateway_url, "enabled": True}
    if auth_token:
        entry["headers"] = {"Authorization": f"Bearer {auth_token}"}

    if "vhir" in mcp:
        results.append("mcp: vhir already configured (updated URL)")
    else:
        results.append("mcp: added vhir server")
    mcp["vhir"] = entry
    _write_json(oc_config_path, oc_config)
    results.append(f"mcp: wrote {oc_config_path}")

    # 2. TypeScript plugin
    if not with_hook:
        results.append("hook: skipped (--no-hook)")
    else:
        plugin_dir.mkdir(parents=True, exist_ok=True)
        plugin_path = plugin_dir / "sift-policy-gate.ts"

        plugin_code = _OPENCODE_PLUGIN_TEMPLATE.format(python_bin=_gate_python())

        if plugin_path.exists():
            results.append("hook: plugin already installed (overwritten)")
        else:
            results.append("hook: installed policy gate plugin")
        plugin_path.write_text(plugin_code)
        results.append(f"hook: wrote {plugin_path}")

    # 3. Forensic discipline instructions
    results.append(_install_discipline("opencode", project_dir, scope))

    return results


# ──────────────────────────── install: pi ─────────────────────────────────────

_PI_EXTENSION_TEMPLATE = '''\
/**
 * SIFT policy gate + bwrap sandbox extension for Pi / oh-my-pi.
 *
 * Intercepts tool_call events for bash, evaluates them against the OPA
 * policy engine, and mutates event.input.command to wrap in bubblewrap.
 *
 * Generated by: python3 -m sift_mcp.setup
 */

import type {{ HookAPI }} from "@oh-my-pi/pi-coding-agent/extensibility/hooks";
import {{ execSync }} from "child_process";

export default function siftPolicyGate(pi: HookAPI): void {{
  pi.on("tool_call", async (event, _ctx) => {{
    if (event.toolName !== "bash") return;
    const cmd = String(event.input.command ?? "").trim();
    if (!cmd) return;

    let result;
    try {{
      result = execSync(
        `{python_bin} -m sift_mcp.hooks.gate`,
        {{
          input: JSON.stringify({{ command: cmd }}),
          timeout: 10000,
          stdio: ["pipe", "pipe", "pipe"],
          env: process.env,
        }}
      );
    }} catch (err: any) {{
      if (err.status === 2) {{
        const reason = (err.stderr?.toString() ?? "").trim()
          || "denied by sift-mcp policy";
        return {{ block: true, reason }};
      }}
      // Non-2 error — fail open
      const msg = err.stderr?.toString().trim() || err.message;
      console.warn(`[sift-policy] gate error (fail-open): ${{msg}}`);
      return;
    }}

    // If gate returned JSON on stdout, apply the sandboxed command rewrite
    const stdout = result?.toString().trim();
    if (stdout) {{
      try {{
        const decision = JSON.parse(stdout);
        if (decision.command) {{
          event.input.command = decision.command;  // mutable per pi docs
        }}
      }} catch {{
        // Not JSON — gate allowed without modification
      }}
    }}
  }});
}}
'''


def install_pi(
    project_dir: str,
    gateway_url: str,
    auth_token: str = "",
    scope: str = "user",
    transport: str = "http",
    gateway_config: str = "",
    with_hook: bool = True,
) -> list[str]:
    """Install MCP config + TypeScript extension for Pi.

    user scope (default) writes under ~/.pi (global); project scope writes into
    ./.mcp.json and ./.pi (or ./.omp) hooks.

    Only ``transport="http"`` is supported here.
    """
    results = []
    p = Path(project_dir)
    home = Path.home()
    if transport == "stdio":
        results.append("mcp: stdio transport not supported for Pi — using http url")

    if scope == "user":
        mcp_path = home / ".pi" / ".mcp.json"
        hooks_dir = home / ".pi" / "hooks"
    else:
        mcp_path = p / ".mcp.json"
        # Try .omp first (oh-my-pi), fall back to .pi
        hooks_dir = None
        for candidate in [p / ".omp" / "hooks", p / ".pi" / "hooks"]:
            if candidate.parent.exists() or candidate.parent == p / ".pi":
                hooks_dir = candidate
                break
        if hooks_dir is None:
            hooks_dir = p / ".pi" / "hooks"

    # 1. MCP server config (.mcp.json — Pi reads this natively)
    _backup_once(mcp_path)
    mcp = _load_json_lenient(mcp_path)
    servers = mcp.setdefault("mcpServers", {})
    entry: dict = {"type": "http", "url": gateway_url}
    if auth_token:
        entry["headers"] = {"Authorization": f"Bearer {auth_token}"}

    if "vhir" in servers:
        results.append("mcp: vhir already configured (updated URL)")
    else:
        results.append("mcp: added vhir server")
    servers["vhir"] = entry
    _write_json(mcp_path, mcp)
    results.append(f"mcp: wrote {mcp_path}")

    # 2. TypeScript extension
    if not with_hook:
        results.append("hook: skipped (--no-hook)")
    else:
        hooks_dir.mkdir(parents=True, exist_ok=True)
        ext_path = hooks_dir / "sift-policy-gate.ts"
        ext_code = _PI_EXTENSION_TEMPLATE.format(python_bin=_gate_python())

        if ext_path.exists():
            results.append("hook: extension already installed (overwritten)")
        else:
            results.append(f"hook: installed extension at {ext_path}")
        ext_path.write_text(ext_code)

    # 3. Forensic discipline instructions
    results.append(_install_discipline("pi", project_dir, scope))

    return results


# ──────────────────────────── dispatcher ──────────────────────────────────────

_INSTALLERS = {
    "claude-code": install_claude_code,
    "opencode": install_opencode,
    "pi": install_pi,
}


# ──────────────────────── interactive menu ────────────────────────────────────


def interactive_menu(detected: list[HarnessInfo]) -> list[str]:
    """Present an interactive menu and return selected harness IDs."""
    available = [h for h in detected if h.detected]
    unavailable = [h for h in detected if not h.detected]

    if not available:
        print(f"\n{_YELLOW}No supported agent harnesses detected.{_RESET}")
        print("Supported: Claude Code, OpenCode, Pi / oh-my-pi")
        print("\nYou can still install manually with --harness <name>.")
        return []

    _header("Detected Agent Harnesses")
    for i, h in enumerate(available, 1):
        print(f"  {_GREEN}{i}.{_RESET} {_BOLD}{h.name}{_RESET}")
        for s in h.signals:
            print(f"     {_DIM}{s}{_RESET}")

    if unavailable:
        print(f"\n  {_DIM}Not detected:{_RESET}")
        for h in unavailable:
            print(f"  {_DIM}   {h.name}{_RESET}")

    print(f"\n  {_BOLD}A.{_RESET} Install on all detected harnesses")
    print(f"  {_DIM}Q. Quit{_RESET}")

    while True:
        try:
            choice = input(f"\n{_CYAN}Select harness(es) [1-{len(available)}, A, Q]: {_RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return []

        if choice.lower() == "q":
            return []
        if choice.lower() == "a":
            return [h.id for h in available]

        # Support comma-separated numbers: "1,3" or single "2"
        try:
            indices = [int(x.strip()) for x in choice.split(",")]
            selected = []
            for idx in indices:
                if 1 <= idx <= len(available):
                    selected.append(available[idx - 1].id)
                else:
                    print(f"  {_RED}Invalid selection: {idx}{_RESET}")
                    selected = []
                    break
            if selected:
                return selected
        except ValueError:
            print(f"  {_RED}Enter a number, comma-separated numbers, A, or Q.{_RESET}")


# ──────────────────────────── verify ──────────────────────────────────────────


def verify_installation(
    harness_id: str, project_dir: str, scope: str = "user", with_hook: bool = True
) -> list[str]:
    """Post-install verification checks (scope-aware)."""
    issues = []
    p = Path(project_dir)
    home = Path.home()

    if harness_id == "claude-code":
        if scope == "user":
            if not (home / ".claude.json").exists():
                issues.append("missing ~/.claude.json")
            if not (home / ".claude" / "settings.json").exists():
                issues.append("missing ~/.claude/settings.json")
        else:
            if not (p / ".mcp.json").exists():
                issues.append("missing .mcp.json")
            if not (p / ".claude" / "settings.local.json").exists():
                issues.append("missing .claude/settings.local.json")

    elif harness_id == "opencode":
        cfg_dir = (home / ".config" / "opencode") if scope == "user" else p
        if not (cfg_dir / "opencode.jsonc").exists() and not (cfg_dir / "opencode.json").exists():
            issues.append(f"missing opencode.json(c) in {cfg_dir}")
        plugin_dir = cfg_dir / "plugins" if scope == "user" else p / ".opencode" / "plugins"
        if with_hook and not (plugin_dir / "sift-policy-gate.ts").exists():
            issues.append(f"missing plugin: {plugin_dir / 'sift-policy-gate.ts'}")

    elif harness_id == "pi":
        if scope == "user":
            if not (home / ".pi" / ".mcp.json").exists():
                issues.append("missing ~/.pi/.mcp.json")
            if with_hook and not (home / ".pi" / "hooks" / "sift-policy-gate.ts").exists():
                issues.append("missing ~/.pi/hooks/sift-policy-gate.ts")
        else:
            if not (p / ".mcp.json").exists():
                issues.append("missing .mcp.json")
            found_ext = any(
                (d / "sift-policy-gate.ts").exists()
                for d in [p / ".omp" / "hooks", p / ".pi" / "hooks"]
            )
            if not found_ext:
                issues.append("missing sift-policy-gate.ts extension")

    return issues


# ──────────────────────────────── main ────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sift_mcp.setup",
        description="Set up SIFT MCP policy enforcement for agent harnesses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python3 -m sift_mcp.setup                          # interactive
  python3 -m sift_mcp.setup --all                     # all detected
  python3 -m sift_mcp.setup --harness claude-code     # specific harness
  python3 -m sift_mcp.setup --list                    # just detect
  python3 -m sift_mcp.setup --all --global            # global, every project (default scope)
  python3 -m sift_mcp.setup --all --project           # this directory only
  python3 -m sift_mcp.setup --gateway-url http://192.168.8.129:4508/mcp
  python3 -m sift_mcp.setup --auth-token vhir_gw_abc123
""",
    )
    parser.add_argument(
        "--harness",
        choices=list(HARNESS_IDS),
        action="append",
        dest="harnesses",
        help="Harness to configure (repeatable).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Install on all detected harnesses.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Detect and list harnesses without installing.",
    )
    parser.add_argument(
        "--project-dir",
        default=".",
        help="Project directory (default: current directory).",
    )
    parser.add_argument(
        "--gateway-url",
        default=DEFAULT_GATEWAY_URL,
        help=f"sift-gateway MCP endpoint (default: {DEFAULT_GATEWAY_URL}).",
    )
    parser.add_argument(
        "--auth-token",
        default="",
        help="Bearer token for gateway auth (remote deployments).",
    )
    parser.add_argument(
        "--scope",
        choices=["user", "project"],
        default="user",
        help="Install globally for the user (default) or into --project-dir only.",
    )
    parser.add_argument(
        "--global",
        dest="scope",
        action="store_const",
        const="user",
        help="Alias for --scope user (global — applies to every project).",
    )
    parser.add_argument(
        "--project",
        dest="scope",
        action="store_const",
        const="project",
        help="Alias for --scope project (this directory only).",
    )
    parser.add_argument(
        "--no-hook",
        action="store_true",
        help="Install MCP/agents/discipline only — skip the Layer 0 policy "
             "gate hook (for client machines; enforcement stays on the "
             "gateway host).",
    )
    parser.add_argument(
        "--transport",
        choices=["http", "stdio"],
        default="http",
        help=(
            "Claude Code MCP transport. 'http' connects to a running gateway "
            "(--gateway-url); 'stdio' makes Claude Code spawn the gateway on "
            "launch via 'python -m sift_gateway --stdio' (no running service)."
        ),
    )
    parser.add_argument(
        "--gateway-config",
        default="",
        help=(
            "Gateway YAML config for --transport stdio "
            "(default: <repo>/config/gateway.e2e.yaml)."
        ),
    )
    args = parser.parse_args(argv)

    gateway_config = args.gateway_config or str(
        _REPO_ROOT / "config" / "gateway.e2e.yaml"
    )

    project = os.path.abspath(args.project_dir)

    # ── banner ──
    print(f"""
{_BOLD}╔══════════════════════════════════════════════════════╗
║  SIFT MCP — Policy Enforcement Setup                 ║
║  OPA policy engine + bubblewrap sandbox              ║
╚══════════════════════════════════════════════════════╝{_RESET}""")

    # ── prerequisites ──
    _header("Prerequisites")
    prereqs = check_prerequisites()
    all_good = True
    for name, path in prereqs.items():
        if path:
            _ok(f"{name}: {path}")
        elif name == "bwrap":
            _warn(f"{name}: not found (sandbox wrapping will be disabled)")
            _info("Install: sudo apt-get install -y bubblewrap")
        elif name == "opa":
            _warn(f"{name}: not found (policy engine will fall back to security.py)")
            _info("Install: curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static")
        else:
            _err(f"{name}: not found")
            all_good = False

    # ── detection ──
    _header("Harness Detection")
    print(f"  {_DIM}Scanning: {project}{_RESET}")

    detected = detect_all(project)
    for h in detected:
        if h.detected:
            _ok(f"{h.name}")
            for s in h.signals:
                _info(s)
        else:
            print(f"  {_DIM}· {h.name}: not detected{_RESET}")

    if args.list:
        return 0

    # ── selection ──
    if args.all:
        selected = [h.id for h in detected if h.detected]
        if not selected:
            _err("No harnesses detected. Use --harness to install manually.")
            return 1
    elif args.harnesses:
        selected = args.harnesses
    else:
        selected = interactive_menu(detected)

    if not selected:
        print(f"\n{_DIM}Nothing selected. Exiting.{_RESET}")
        return 0

    # ── confirmation ──
    _header("Installation Plan")
    if args.scope == "user":
        print(f"  {_BOLD}Scope:{_RESET} user / global  {_DIM}(applies to every project){_RESET}")
    else:
        print(f"  {_BOLD}Scope:{_RESET} project  {_DIM}({project}){_RESET}")
    for hid in selected:
        info = next(h for h in detected if h.id == hid)
        print(f"  {_BOLD}{info.name}{_RESET}")
        if hid == "claude-code" and args.transport == "stdio":
            print(f"    MCP transport: stdio (spawned on launch)")
            print(f"    Gateway cmd:   {_gate_python()} -m sift_gateway --stdio")
            print(f"    Gateway cfg:   {gateway_config}")
        else:
            print(f"    MCP endpoint:  {args.gateway_url}")
        if args.no_hook:
            print(f"    Policy gate:   skipped (--no-hook; gateway-side enforcement only)")
        else:
            print(f"    Policy gate:   OPA → bwrap sandbox wrapping")
        if hid == "claude-code":
            print(f"    Hook type:     PreToolUse (updatedInput)")
            _subagents = sorted(_SUBAGENTS_SRC.glob("*.md")) if _SUBAGENTS_SRC.is_dir() else []
            if _subagents:
                print(f"    Subagents:     {', '.join(s.stem for s in _subagents)} (→ .claude/agents/)")
        elif hid == "opencode":
            print(f"    Hook type:     TypeScript plugin (tool.execute.before)")
        elif hid == "pi":
            print(f"    Hook type:     TypeScript extension (tool_call)")
        if args.auth_token:
            print(f"    Auth:          Bearer token (set)")
        else:
            print(f"    Auth:          none (localhost)")

    try:
        confirm = input(f"\n{_CYAN}Proceed? [Y/n]: {_RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0

    if confirm and confirm not in ("y", "yes"):
        print(f"\n{_DIM}Cancelled.{_RESET}")
        return 0

    # ── install ──
    _header("Installing")
    all_ok = True

    for hid in selected:
        info = next(h for h in detected if h.id == hid)
        print(f"\n  {_BOLD}{info.name}{_RESET}")
        installer = _INSTALLERS[hid]

        try:
            results = installer(
                project,
                args.gateway_url,
                args.auth_token,
                args.scope,
                args.transport,
                gateway_config,
                not args.no_hook,
            )
            for r in results:
                _ok(r)
        except Exception as exc:
            _err(f"Installation failed: {exc}")
            all_ok = False
            continue

        # Verify
        issues = verify_installation(hid, project, args.scope, not args.no_hook)
        if issues:
            for issue in issues:
                _warn(f"verify: {issue}")
            all_ok = False
        else:
            _ok("verified")

    # ── summary ──
    _header("Summary")
    if all_ok:
        _ok("All installations completed successfully")
    else:
        _warn("Some installations had warnings — review above")

    # Post-install notes
    print(f"""
{_DIM}Next steps:
  1. Start the sift-gateway:  cd {_REPO_ROOT} && python -m sift_gateway
  2. Enable policy engine:    export SIFT_POLICY_ENGINE=1
  3. Enable sandbox:          export SIFT_SANDBOX=1
  4. Launch your agent and verify with:
       run_command("ls /evidence")       # should work (sandboxed)
       run_command("touch /evidence/x")  # should fail (EROFS){_RESET}
""")

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())