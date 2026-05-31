"""Generate and install harness hook configuration for policy enforcement.

Writes the correct hook config for the detected or specified agent harness
so that direct bash/shell commands are evaluated against the OPA policy
engine before execution. This closes the bypass gap where an agent uses
its native bash tool instead of sift-mcp's run_command.

Usage:
    python3 -m sift_mcp.hooks.install --harness claude-code
    python3 -m sift_mcp.hooks.install --harness opencode
    python3 -m sift_mcp.hooks.install --harness pi
    python3 -m sift_mcp.hooks.install --detect          # auto-detect

Each harness writes config to its standard location. Existing config is
merged (hooks are appended, not overwritten).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------

def _claude_code_hook_entry() -> dict:
    """The PreToolUse hook entry for Claude Code settings.json."""
    return {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": f"{sys.executable} -m sift_mcp.hooks.gate",
                "timeout": 5,
            }
        ],
    }


def install_claude_code(project_dir: str) -> str:
    """Write or merge hook config into .claude/settings.local.json."""
    claude_dir = Path(project_dir) / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    settings_path = claude_dir / "settings.local.json"

    if settings_path.exists():
        settings = json.loads(settings_path.read_text())
    else:
        settings = {}

    hooks = settings.setdefault("hooks", {})
    pre_tool = hooks.setdefault("PreToolUse", [])

    # Check if our hook is already installed (by command match).
    gate_cmd = f"{sys.executable} -m sift_mcp.hooks.gate"
    already = any(
        any(h.get("command", "").endswith("sift_mcp.hooks.gate") for h in entry.get("hooks", []))
        for entry in pre_tool
    )
    if already:
        return f"Already installed in {settings_path}"

    pre_tool.append(_claude_code_hook_entry())
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    return f"Installed Claude Code hook in {settings_path}"


# ---------------------------------------------------------------------------
# OpenCode
# ---------------------------------------------------------------------------

def _opencode_hook_entry() -> dict:
    """The tool.before.bash hook entry for OpenCode hooks.yaml."""
    return {
        "event": "tool.before.bash",
        "action": "stop",
        "actions": [
            {
                "bash": {
                    "command": (
                        f'echo "$OPENCODE_TOOL_ARGS" | '
                        f"{sys.executable} -m sift_mcp.hooks.gate"
                    ),
                    "timeout": 5000,
                }
            }
        ],
    }


def install_opencode(project_dir: str) -> str:
    """Write or merge hook config into .opencode/hooks.yaml."""
    oc_dir = Path(project_dir) / ".opencode"
    oc_dir.mkdir(parents=True, exist_ok=True)
    hooks_path = oc_dir / "hooks.yaml"

    if hooks_path.exists():
        config = yaml.safe_load(hooks_path.read_text()) or {}
    else:
        config = {}

    hook_list = config.setdefault("hooks", [])

    # Check if already installed.
    already = any(
        h.get("event") == "tool.before.bash"
        and any(
            "sift_mcp.hooks.gate" in str(a.get("bash", {}).get("command", ""))
            for a in h.get("actions", [])
        )
        for h in hook_list
    )
    if already:
        return f"Already installed in {hooks_path}"

    hook_list.append(_opencode_hook_entry())
    hooks_path.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False))
    return f"Installed OpenCode hook in {hooks_path}"


# ---------------------------------------------------------------------------
# Pi (oh-my-pi / earendil-works/pi)
# ---------------------------------------------------------------------------

def install_pi(project_dir: str) -> str:
    """Set up the Pi TypeScript extension hook.

    Pi hooks are TypeScript modules, not shell commands. We copy our
    pi_extension.ts to the project's Pi hook directory and print
    instructions for adding it to Pi's config.
    """
    import shutil

    src = Path(__file__).parent / "pi_extension.ts"
    if not src.exists():
        return f"Error: pi_extension.ts not found at {src}"

    # Pi looks for hooks in several places. .pi/hooks/ is conventional.
    pi_hooks_dir = Path(project_dir) / ".pi" / "hooks"
    pi_hooks_dir.mkdir(parents=True, exist_ok=True)
    dest = pi_hooks_dir / "sift-policy-gate.ts"

    if dest.exists():
        return f"Already installed at {dest}"

    shutil.copy2(src, dest)
    return (
        f"Installed Pi hook at {dest}\n"
        f"Add to Pi config: --hook {dest}\n"
        f"Or add to .pi/config: hooks: [\"{dest}\"]"
    )


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------

def detect_harness(project_dir: str) -> str | None:
    """Detect which agent harness is in use based on config files."""
    p = Path(project_dir)

    # Claude Code: .claude/ directory or CLAUDE.md
    if (p / ".claude").is_dir() or (p / "CLAUDE.md").exists():
        return "claude-code"

    # OpenCode: .opencode/ directory
    if (p / ".opencode").is_dir():
        return "opencode"

    # Pi: .pi/ directory or pi.config.*
    if (p / ".pi").is_dir() or list(p.glob("pi.config.*")):
        return "pi"

    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_INSTALLERS = {
    "claude-code": install_claude_code,
    "opencode": install_opencode,
    "pi": install_pi,
}


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="sift_mcp.hooks.install",
        description="Install policy gate hooks for agent harnesses.",
    )
    parser.add_argument(
        "--harness",
        choices=list(_INSTALLERS.keys()),
        help="Agent harness to configure.",
    )
    parser.add_argument(
        "--detect",
        action="store_true",
        help="Auto-detect harness from project directory.",
    )
    parser.add_argument(
        "--project-dir",
        default=".",
        help="Project directory (default: current directory).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Install hooks for all supported harnesses.",
    )
    args = parser.parse_args(argv)

    project = os.path.abspath(args.project_dir)

    if args.all:
        for name, installer in _INSTALLERS.items():
            result = installer(project)
            print(f"[{name}] {result}")
        return 0

    harness = args.harness
    if not harness and args.detect:
        harness = detect_harness(project)
        if not harness:
            print(
                "Could not detect harness. Use --harness to specify one, "
                "or --all to install for all supported harnesses.",
                file=sys.stderr,
            )
            return 1
        print(f"Detected harness: {harness}")

    if not harness:
        parser.print_help()
        return 1

    result = _INSTALLERS[harness](project)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
