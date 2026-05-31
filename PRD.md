# Find Evil! Hackathon — MVP Specification

## Project: Policy-as-Code Enforcement & Sandbox Isolation for AIIR

**Author:** Jared Gore
**Hackathon:** Find Evil! (SANS Institute, Devpost)
**Deadline:** June 15, 2026
**Codebase:** Fork of [AppliedIR/sift-mcp](https://github.com/AppliedIR/sift-mcp) (MIT License)
**Architectural Pattern:** Custom MCP Server (Pattern #2)

---

## 1. Problem Statement

AIIR (AppliedIR/sift-mcp) is the most mature AI-assisted DFIR platform targeting the SIFT Workstation. It enforces forensic discipline through:

- A YAML-defined security policy (`security.yaml`) consumed by hardcoded Python enforcement (`security.py`)
- Per-tool flag restrictions (e.g., `find` blocks `-exec`, `sed` blocks `-i`)
- HMAC-signed findings and audit trails

**Critically, sift-mcp has zero kernel-level isolation.** All enforcement is Python application-level checks. The separate Valhuntir CLI project (`AppliedIR/Valhuntir`) deploys a bubblewrap sandbox, but only when Claude Code is the LLM client and only when installed via the Valhuntir installer. The sift-mcp codebase itself — the MCP servers, gateway, and execution pipeline — runs tool commands directly on the host via `subprocess.run()` with no OS-level protection.

These controls have structural limitations:

1. **Policy data is separated from enforcement, but enforcement is hardcoded.** `security.yaml` defines what's blocked. `security.py` implements how it's checked. But the implementation is imperative Python — five separate functions (`sanitize_extra_args()`, `is_denied()`, `validate_rm_targets()`, `validate_output_path()`, `validate_input_path()`) with interleaved concerns. Adding a new policy category means writing new Python code, not just adding YAML.
2. **Policy decisions are binary and opaque.** Every check raises `ValueError` with a string message. There's no structured decision record, no list of all policies evaluated, no suggested alternatives. The agent gets a Python exception, not actionable feedback.
3. **No kernel-level isolation in the MCP execution path.** A bug in `security.py`, a creative flag combination, or a tool that behaves unexpectedly can modify evidence. The application-level denylist is the only thing between the agent and destructive commands.
4. **No composability.** You can't layer case-specific policies on top of defaults. There's one `security.yaml` for all cases, all tools, all contexts.

Protocol SIFT (SANS's baseline) has none of these controls — it's Claude Code with prompt files. The gap between "prompts and vibes" and "production DFIR" is the enforcement layer.

## 2. Existing Enforcement: security.yaml → security.py

Understanding the exact current implementation is critical because we're not replacing the YAML format — we're replacing the Python evaluation engine underneath it.

### 2.1 security.yaml Structure

The existing policy file defines five categories:

```yaml
# Global flags blocked on any tool (unless tool_allowed_flags grants an exception)
dangerous_flags:
  - "-e"
  - "--exec"
  - "--command"
  - "-enc"
  - "-encodedcommand"
  - "--script"
  - "--invoke"

# Per-tool exceptions to the global dangerous_flags list
tool_allowed_flags:
  run_bulk_extractor:
    - "-e"
    - "-x"

# Per-tool flags that are always blocked (regardless of global list)
tool_blocked_flags:
  find:
    - "-exec"
    - "-execdir"
    - "-delete"
    - "-fls"
    - "-fprint"
    - "-fprint0"
    - "-fprintf"
  sed:
    - "-i"
    - "--in-place"
  tar:
    - "-x"
    - "--extract"
    - "--get"
    - "-c"
    - "--create"
    - "--delete"
    - "--append"
    - "--checkpoint-action"
    - "--use-compress-program"
    - "--to-command"
  unzip:
    - "-o"
    - "-n"

# Flags that indicate the next arg is an output path (triggers output path validation)
output_flags:
  - "--csv"
  - "--csvf"
  - "-o"
  - "--output"
  - "--json"
  - "--jsonl"

# Binaries that are unconditionally blocked
denied_binaries:
  - "mkfs"
  - "mkfs.ext4"
  - "mkfs.xfs"
  - "mkfs.btrfs"
  - "mkfs.ntfs"
  - "shutdown"
  - "reboot"
  - "poweroff"
  - "halt"
  - "init"
  - "kill"
  - "killall"
  - "pkill"
  - "env"
  - "printenv"
  - "nc"
  - "ncat"
```

### 2.2 security.py Functions (What Gets Replaced)

| Function | What It Does | How It Decides | Limitation |
|----------|-------------|----------------|------------|
| `is_denied(binary)` | Checks `denied_binaries` list | `binary.lower() in list` | Binary pass/fail, no reason string, no context |
| `sanitize_extra_args(args, tool)` | Checks global `dangerous_flags`, per-tool `tool_blocked_flags`, per-tool `tool_allowed_flags` exceptions, shell metacharacters (`;`, `&&`, `\|\|`, backtick, `$(`, `${`), awk program text scanning | Iterates args, raises `ValueError` on first match | Stops at first violation — doesn't report all violations. No suggested alternatives. |
| `validate_rm_targets(args)` | Blocks `rm` in protected dirs (`/cases`, `/evidence`, case dir) | Path resolution + startswith checks | Hardcoded protected paths. Has guidance message but it's a string, not structured data. |
| `validate_output_path(path)` | Ensures output goes to case dir or `/tmp` | Resolves path, checks case dir containment, then blocked dir list | Different blocked dir list than input validation. Logic is interleaved. |
| `validate_input_path(path)` | Blocks reads from system dirs (`/etc`, `/proc`, `/sys`, `/dev`, `/boot`, `~/.vhir`) | Resolves path, checks against blocklist, with exceptions for `~/.vhir/cases` and `~/.vhir/hayabusa-output` | Hardcoded exceptions. |

### 2.3 What We Keep vs. What We Replace

| Component | Keep / Replace | Rationale |
|-----------|---------------|-----------|
| `security.yaml` format | **Keep + extend** | Practitioners already know it. It's the authoring interface. |
| `security.py` evaluation | **Replace with OPA** | Declarative evaluation produces structured decisions with all violation reasons, not just the first. |
| `_DANGEROUS_PATTERNS` (shell metacharacters) | **Migrate to Rego** | Same checks, declarative form. |
| Awk program text regex | **Migrate to Rego** | Same regex, cleaner expression as a Rego rule. |
| Path validation logic | **Migrate to Rego** | Same resolution + blocklist checks, composable per-case. |
| `load_security_policy()` from catalog | **Replace with YAML→Rego compiler** | YAML is compiled to Rego policies + OPA data.json. OPA loads both. |

---

## 3. Proposed Solution

Two complementary enforcement layers added to the AIIR sift-mcp codebase:

### Layer 1: YAML → Rego Compilation + OPA Evaluation

Instead of asking practitioners to learn Rego, we keep `security.yaml` as the authoring format and compile it to Rego behind the scenes. Inspired by [yaml-opa-llm-guardrails](https://github.com/aatakansalar/yaml-opa-llm-guardrails), which uses Jinja2 templates to generate Rego from YAML definitions.

**The flow:**

```
Practitioner edits security.yaml
    → Pydantic validates the schema
    → Jinja2 templates generate .rego policy files
    → data.json generated from YAML lists (denied_binaries, tool_blocked_flags, etc.)
    → OPA loads compiled policies + data
    → run_command calls OPA for evaluation
    → Structured allow/deny with ALL violation reasons returned
```

**Why this approach over hand-written Rego:**

- **Zero new languages for practitioners.** Steve Anson and IR professionals keep editing YAML.
- **OPA's benefits without OPA's learning curve.** Composability, structured decisions, audit trails — all from familiar YAML.
- **Escape hatch for power users.** A `custom` rule type allows raw Rego for complex logic that YAML can't express.
- **The compiler is the contribution.** A YAML→Rego compiler purpose-built for agentic tool execution policies, not LLM content filtering.

### Layer 2: Bubblewrap (bwrap) Sandbox Isolation

Wrap every tool invocation in a bubblewrap sandbox at the MCP execution layer. Unlike the Valhuntir CLI's bwrap deployment (which is Claude Code-specific and lives outside sift-mcp), this integration lives directly in the `run_command` execution path — every tool call through any MCP client gets sandboxed.

**Why bwrap:**

- **SIFT tools are already on the host.** The whole point of the SIFT VM is 200+ forensic tools installed and configured. Docker means rebuilding that in a container image. bwrap wraps the existing tools in a namespace — no image to build, no subset to choose, no image to maintain.
- **Alignment with the broader ecosystem.** Valhuntir already chose bwrap for its Claude Code sandbox. Using the same primitive makes the upstream PR story cleaner.
- **Lightweight and per-invocation.** No daemon, no overlay filesystem, no persistent state. Each tool invocation gets its own namespace that exits when the tool exits. Zero lifecycle management.
- **Does exactly what we need.** Read-only bind mounts for evidence, network namespace isolation, capability dropping — all in one `bwrap` call with no moving parts.

### How They Compose

```
Agent calls run_command("find /evidence -exec rm {} \;")
    │
    ├─ Layer 1 (YAML→Rego→OPA): Policy evaluation
    │   security.yaml compiled to Rego at startup
    │   Input:  {tool: "find", args: [...], flags: ["-exec"], paths: ["/evidence"]}
    │   Compiled policy: tool_blocked_flags.rego → DENY "-exec on find"
    │   Result: Denied with ALL matching reasons (not just first)
    │   Action: Return structured denial to agent via MCP response envelope
    │
    └─ Layer 2 (bwrap): Kernel enforcement (if OPA had allowed)
        bwrap --ro-bind /evidence /evidence -- <tool> <args>
        Even if policy had a gap, the kernel blocks writes to /evidence
        --unshare-net prevents exfiltration
        Process exits, namespace is gone — no cleanup needed
```

Defense in depth: OPA catches known-bad patterns and returns helpful feedback. bwrap catches everything else silently at the kernel level.

---

## 4. MVP Scope (2-Day Hack)

### What's In

- YAML→Rego compiler that converts `security.yaml` into OPA-evaluable policies
- Pydantic schema validation for security.yaml
- Jinja2 templates for each policy category
- OPA evaluation wired into AIIR's `run_command` execution pipeline (wrapping existing `security.py`)
- Structured MCP denial responses with all violation reasons
- bwrap sandbox wrapping every `subprocess.run()` call with evidence read-only + network isolation
- Policy decisions logged to AIIR's existing audit trail format
- End-to-end demo: allow → deny → kernel block

### What's Out (MVP)

- Custom Claude Code PreToolUse hook adapter
- `custom` rule type with raw Rego escape hatch (post-MVP)
- Per-case policy overrides / policy layering
- OPA bundle hot-reload
- UI for policy management
- Integration with AIIR's HMAC signing or examiner portal
- seccomp-bpf profiles (bwrap supports these but they add complexity for MVP)

---

## 5. Architecture

### 5.1 Package Structure (new additions to AIIR monorepo)

```
packages/
├── policy-engine/              # NEW — YAML→Rego compiler + OPA integration
│   ├── __init__.py
│   ├── compiler.py             # YAML→Rego compilation (Jinja2)
│   ├── evaluator.py            # OPA evaluation interface
│   ├── parser.py               # Parse run_command call into OPA input document
│   ├── schema.py               # Pydantic models for security.yaml validation
│   ├── templates/              # Jinja2 templates for Rego generation
│   │   ├── denied_binaries.rego.j2
│   │   ├── dangerous_flags.rego.j2
│   │   ├── tool_blocked_flags.rego.j2
│   │   ├── shell_metacharacters.rego.j2
│   │   ├── awk_scanning.rego.j2
│   │   ├── path_policy.rego.j2
│   │   ├── output_path_policy.rego.j2
│   │   └── rm_protection.rego.j2
│   ├── compiled/               # Generated .rego files + data.json (gitignored)
│   │   └── ...
│   └── audit.py                # Policy decision audit logging
│
├── sandbox/                    # NEW — bwrap execution wrapper
│   ├── __init__.py
│   ├── bwrap.py                # bwrap command construction + execution
│   ├── config.py               # Sandbox configuration (paths, capabilities)
│   └── profiles/               # Named sandbox profiles
│       ├── default.yaml        # Standard forensic analysis profile
│       └── strict.yaml         # Maximum isolation profile
│
├── sift-mcp/                   # EXISTING — modified
│   ├── data/catalog/
│   │   └── security.yaml       # EXISTING — kept as-is, now also compiled to Rego
│   └── src/sift_mcp/
│       ├── security.py         # EXISTING — kept as fallback, OPA evaluation added before it
│       └── ...
│
└── sift-common/                # EXISTING — extended
    └── (shared config for policy_engine and sandbox settings)
```

### 5.2 YAML → Rego Compilation

The compiler reads `security.yaml` and produces two outputs:

**1. `data.json`** — The YAML lists converted to OPA's data format:

```json
{
  "denied_binaries": ["mkfs", "mkfs.ext4", "mkfs.xfs", "shutdown", "reboot", "..."],
  "dangerous_flags": ["-e", "--exec", "--command", "-enc", "..."],
  "tool_allowed_flags": {
    "run_bulk_extractor": ["-e", "-x"]
  },
  "tool_blocked_flags": {
    "find": ["-exec", "-execdir", "-delete", "-fls", "-fprint", "-fprint0", "-fprintf"],
    "sed": ["-i", "--in-place"],
    "tar": ["-x", "--extract", "--get", "-c", "--create", "--delete", "--append",
            "--checkpoint-action", "--use-compress-program", "--to-command"],
    "unzip": ["-o", "-n"]
  },
  "output_flags": ["--csv", "--csvf", "-o", "--output", "--json", "--jsonl"],
  "shell_metacharacters": [";", "&&", "||", "`", "$(", "${"],
  "blocked_input_dirs": ["/etc", "/proc", "/sys", "/dev", "/boot"],
  "blocked_output_dirs": ["/etc", "/proc", "/sys", "/dev", "/boot", "/usr", "/bin",
                          "/sbin", "/lib", "/var", "/home"],
  "protected_rm_dirs": ["/cases", "/evidence"],
  "awk_program_tools": ["awk", "gawk", "mawk", "nawk"]
}
```

**2. Generated `.rego` files** from Jinja2 templates. Example `tool_blocked_flags.rego.j2`:

```
# Generated from security.yaml — do not edit directly
package sift.tool_blocked_flags

import rego.v1

deny contains msg if {
    blocked := data.tool_blocked_flags[input.tool]
    some flag in input.flags
    lower(flag) in blocked
    msg := sprintf("BLOCKED: flag '%s' is not permitted on '%s'", [flag, input.tool])
}

# Global dangerous flags (with per-tool exceptions)
deny contains msg if {
    some flag in input.flags
    lower(flag) in data.dangerous_flags
    not _has_exception(input.tool, flag)
    msg := sprintf("BLOCKED: flag '%s' is globally dangerous", [flag])
}

_has_exception(tool, flag) if {
    exceptions := data.tool_allowed_flags[tool]
    lower(flag) in exceptions
}
```

Example `shell_metacharacters.rego.j2`:

```
# Generated from security.yaml — do not edit directly
package sift.shell_metacharacters

import rego.v1

deny contains msg if {
    some arg in input.args
    some pattern in data.shell_metacharacters
    contains(arg, pattern)
    msg := sprintf("BLOCKED: shell metacharacter '%s' detected in argument", [pattern])
}
```

Example `awk_scanning.rego.j2`:

```
# Generated from security.yaml — do not edit directly
package sift.awk_scanning

import rego.v1

deny contains msg if {
    input.tool in data.awk_program_tools
    some arg in input.args
    not startswith(arg, "-")
    re_match(`system\s*\(|getline|".*\||>>\s*"`, arg)
    msg := sprintf("BLOCKED: dangerous construct in %s program text (system(), getline, pipes)", [input.tool])
}
```

Example `rm_protection.rego.j2`:

```
# Generated from security.yaml — do not edit directly
package sift.rm_protection

import rego.v1

deny contains msg if {
    input.tool == "rm"
    some path in input.paths
    some protected in data.protected_rm_dirs
    startswith(path, protected)
    msg := sprintf(
        "BLOCKED: rm in protected directory '%s'. File deletion in case/evidence directories requires human action outside the AI session.",
        [protected]
    )
}

deny contains msg if {
    input.tool == "rm"
    some path in input.paths
    path == "/"
    msg := "BLOCKED: rm targeting filesystem root"
}
```

### 5.3 Compilation Trigger

The compiler runs:
- **At startup** when the MCP server initializes (compile once, evaluate many)
- **On config reload** if security.yaml changes
- **Via CLI** for development/testing: `python -m policy_engine.compiler compile security.yaml --output compiled/`

### 5.4 Execution Pipeline (Modified)

Current AIIR pipeline:

```
MCP tool call → security.py checks (5 functions, raise ValueError) → subprocess.run() → parse → enrich → audit
```

Modified pipeline (MVP — OPA wraps security.py, bwrap wraps subprocess):

```
MCP tool call
    → parser.py: serialize tool call into OPA input document
    → evaluator.py: call OPA with compiled policies
    → if ANY deny rules match:
        return structured MCP denial with ALL reasons
        log policy decision to audit trail
        STOP
    → if all policies ALLOW:
        security.py runs as fallback (belt + suspenders for MVP)
        → sandbox/bwrap.py: construct bwrap wrapper around the command
        → bwrap executes tool in sandboxed namespace:
            evidence paths: read-only bind mount
            output path: read-write bind mount
            network: unshared (isolated)
            capabilities: dropped
        → parse output → enrich with forensic-knowledge → audit
```

### 5.5 Bubblewrap Sandbox Implementation

#### 5.5.1 What bwrap Does

Bubblewrap (`bwrap`) is a lightweight, unprivileged sandboxing tool that uses Linux namespaces. It's a single binary (~40KB) that creates isolated environments per process invocation. No daemon, no images, no persistent state. When the wrapped process exits, the namespace is gone.

Key namespaces used:

| Namespace | Flag | What It Isolates |
|-----------|------|-----------------|
| Mount | `--ro-bind`, `--bind` | Filesystem visibility and write permissions |
| Network | `--unshare-net` | Prevents all network access |
| PID | `--unshare-pid` | Hides host processes from sandboxed tool |
| IPC | `--unshare-ipc` | Isolates inter-process communication |

#### 5.5.2 Installation

bwrap is available in Ubuntu repos (the SIFT Workstation is Ubuntu-based):

```bash
sudo apt-get install -y bubblewrap
```

Verify: `bwrap --version`

No configuration, no daemon, no service to manage.

#### 5.5.3 Sandbox Profiles

Profiles define the bind mount layout and namespace flags for a given execution context. Stored as YAML in `packages/sandbox/profiles/`.

**`default.yaml`** — Standard forensic analysis:

```yaml
# Default sandbox profile for forensic tool execution on SIFT Workstation
name: default
description: "Standard forensic analysis — evidence read-only, network isolated"

# Filesystem binds
bind_mounts:
  read_only:
    # SIFT tools and system libraries (tools are on the host, we just expose them)
    - /usr
    - /bin
    - /sbin
    - /lib
    - /lib64
    - /opt                  # Zimmerman tools, hayabusa, etc. live here
    # Evidence paths — always read-only
    - /evidence
    - /mnt                  # Common mount point for disk images
  read_write:
    - /output               # Analysis output
    - /tmp                  # Scratch space for tool working data
  # These are dynamically added from case context:
  # - {case_dir}/output → /output (rw)
  # - {evidence_path} → /evidence (ro)

# Special mounts
proc: true                  # Mount /proc (required by many tools)
dev: minimal                # Mount /dev/null, /dev/zero, /dev/urandom only (--dev /dev)
tmpfs:
  - path: /tmp
    size: 1G

# Namespace isolation
unshare:
  - net                     # No network access
  - pid                     # Can't see host processes
  - ipc                     # Isolate IPC

# Process settings
die_with_parent: true       # Kill sandboxed process if parent (MCP server) dies
new_session: true           # Prevent terminal escape via TIOCSTI
```

**`strict.yaml`** — Maximum isolation for untrusted cases:

```yaml
name: strict
description: "Maximum isolation — minimal filesystem, no network, no /proc"

bind_mounts:
  read_only:
    - /usr/bin
    - /usr/sbin
    - /usr/lib
    - /lib
    - /lib64
    - /evidence
  read_write:
    - /output

proc: false                 # No /proc access
dev: minimal
tmpfs:
  - path: /tmp
    size: 512M

unshare:
  - net
  - pid
  - ipc
  - uts                     # Isolate hostname

die_with_parent: true
new_session: true
```

#### 5.5.4 bwrap.py — Command Construction

The core module that translates a sandbox profile + tool command into a bwrap invocation.

```python
"""Bubblewrap sandbox wrapper for forensic tool execution."""

from __future__ import annotations
import subprocess
import shutil
from pathlib import Path
from typing import Optional
import yaml

class SandboxError(Exception):
    """Raised when sandbox setup or execution fails."""
    pass

class BwrapSandbox:
    """Construct and execute bwrap-wrapped tool commands."""

    def __init__(self, profile_path: str = "profiles/default.yaml"):
        self.profile = self._load_profile(profile_path)
        self._verify_bwrap()

    def _verify_bwrap(self) -> None:
        """Ensure bwrap binary is available."""
        if not shutil.which("bwrap"):
            raise SandboxError(
                "bubblewrap (bwrap) not found. Install with: "
                "sudo apt-get install -y bubblewrap"
            )

    def _load_profile(self, path: str) -> dict:
        """Load and validate a sandbox profile."""
        with open(path) as f:
            return yaml.safe_load(f)

    def build_command(
        self,
        tool: str,
        args: list[str],
        evidence_path: Optional[str] = None,
        output_path: Optional[str] = None,
        case_dir: Optional[str] = None,
    ) -> list[str]:
        """Build the full bwrap command line from profile + tool invocation.

        Returns a list suitable for subprocess.run().
        """
        cmd = ["bwrap"]

        # Read-only bind mounts
        for path in self.profile["bind_mounts"]["read_only"]:
            resolved = str(Path(path).resolve())
            if Path(resolved).exists():
                cmd.extend(["--ro-bind", resolved, resolved])

        # Dynamic evidence mount (always read-only)
        if evidence_path:
            resolved = str(Path(evidence_path).resolve())
            cmd.extend(["--ro-bind", resolved, "/evidence"])

        # Read-write bind mounts
        for path in self.profile["bind_mounts"]["read_write"]:
            if path == "/output" and output_path:
                resolved = str(Path(output_path).resolve())
                cmd.extend(["--bind", resolved, "/output"])
            elif path == "/tmp":
                pass  # Handled by tmpfs below
            else:
                resolved = str(Path(path).resolve())
                if Path(resolved).exists():
                    cmd.extend(["--bind", resolved, resolved])

        # Case directory output (read-write)
        if case_dir and not output_path:
            output_dir = str(Path(case_dir).resolve() / "output")
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            cmd.extend(["--bind", output_dir, "/output"])

        # Special mounts
        if self.profile.get("dev") == "minimal":
            cmd.extend(["--dev", "/dev"])
        if self.profile.get("proc"):
            cmd.extend(["--proc", "/proc"])

        # tmpfs mounts
        for tmpfs in self.profile.get("tmpfs", []):
            cmd.extend(["--tmpfs", tmpfs["path"]])

        # Namespace isolation
        for ns in self.profile.get("unshare", []):
            cmd.append(f"--unshare-{ns}")

        # Process settings
        if self.profile.get("die_with_parent"):
            cmd.append("--die-with-parent")
        if self.profile.get("new_session"):
            cmd.append("--new-session")

        # The tool command itself
        cmd.append("--")
        cmd.append(tool)
        cmd.extend(args)

        return cmd

    def execute(
        self,
        tool: str,
        args: list[str],
        evidence_path: Optional[str] = None,
        output_path: Optional[str] = None,
        case_dir: Optional[str] = None,
        timeout: int = 600,
    ) -> subprocess.CompletedProcess:
        """Execute a tool inside the bwrap sandbox.

        Returns subprocess.CompletedProcess with stdout, stderr, returncode.
        """
        cmd = self.build_command(
            tool=tool,
            args=args,
            evidence_path=evidence_path,
            output_path=output_path,
            case_dir=case_dir,
        )

        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            # No shell=True — bwrap is the process, tool is its child
        )
```

#### 5.5.5 What a Sandboxed Invocation Looks Like

When the agent calls `run_command("vol3 -f /evidence/memory.raw windows.pslist")`, the sandbox constructs:

```bash
bwrap \
  --ro-bind /usr /usr \
  --ro-bind /bin /bin \
  --ro-bind /sbin /sbin \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /opt /opt \
  --ro-bind /cases/CASE-001/evidence /evidence \
  --bind /cases/CASE-001/output /output \
  --dev /dev \
  --proc /proc \
  --tmpfs /tmp \
  --unshare-net \
  --unshare-pid \
  --unshare-ipc \
  --die-with-parent \
  --new-session \
  -- vol3 -f /evidence/memory.raw windows.pslist
```

Key properties:
- `vol3` sees `/evidence/memory.raw` as read-only — kernel-enforced, not application-enforced
- No network access — `--unshare-net` means no sockets, no DNS, no exfiltration
- Can't see host processes — `--unshare-pid` isolates the PID namespace
- Tool output goes to `/output` which maps to the case output directory (read-write)
- `/tmp` is ephemeral tmpfs — disappears when the tool exits
- `--die-with-parent` ensures the sandboxed process dies if the MCP server crashes
- When `vol3` exits, the namespace is gone. No cleanup, no teardown, no state.

#### 5.5.6 Integration with run_command

The change to the existing execution path is minimal. Where sift-mcp currently does:

```python
result = subprocess.run(cmd, shell=False, capture_output=True, ...)
```

It becomes:

```python
if config.sandbox_enabled:
    sandbox = BwrapSandbox(profile=config.sandbox_profile)
    result = sandbox.execute(
        tool=binary_name,
        args=extra_args,
        evidence_path=case_evidence_path,
        output_path=case_output_path,
        case_dir=case_dir,
    )
else:
    result = subprocess.run(cmd, shell=False, capture_output=True, ...)
```

That's it. The bwrap sandbox is a transparent wrapper around `subprocess.run()`. The MCP response envelope, forensic-knowledge enrichment, and audit logging work identically — they operate on `result.stdout` / `result.stderr` regardless of whether the command was sandboxed.

### 5.6 OPA Input Document Schema

Every tool call is serialized into a standard input document for OPA evaluation:

```json
{
  "tool": "find",
  "raw_command": "find /evidence/disk1 -name '*.evtx' -exec strings {} \\;",
  "args": ["/evidence/disk1", "-name", "*.evtx", "-exec", "strings", "{}", ";"],
  "flags": ["-name", "-exec"],
  "paths": ["/evidence/disk1"],
  "output_paths": [],
  "case_id": "CASE-2026-001",
  "case_dir": "/cases/CASE-2026-001",
  "examiner": "jgore",
  "sandbox_enabled": true,
  "strict_mode": false,
  "timestamp": "2026-06-01T14:30:00Z"
}
```

### 5.7 OPA Decision Output Schema

```json
{
  "allowed": false,
  "reasons": [
    "sift.tool_blocked_flags: flag '-exec' is not permitted on 'find'",
    "sift.shell_metacharacters: shell metacharacter ';' detected in argument"
  ],
  "policies_evaluated": [
    "sift.denied_binaries",
    "sift.tool_blocked_flags",
    "sift.dangerous_flags",
    "sift.shell_metacharacters",
    "sift.awk_scanning",
    "sift.rm_protection",
    "sift.path_policy",
    "sift.output_path_policy"
  ],
  "timestamp": "2026-06-01T14:30:00.123Z"
}
```

### 5.8 MCP Denial Response Envelope

```json
{
  "success": false,
  "tool": "run_command",
  "error_type": "policy_denial",
  "policy_decision": {
    "allowed": false,
    "reasons": [
      "sift.tool_blocked_flags: flag '-exec' is not permitted on 'find'",
      "sift.shell_metacharacters: shell metacharacter ';' detected in argument"
    ],
    "policies_evaluated": 8
  },
  "discipline_reminder": "Policy denials are guardrails, not obstacles. Reformulate your command within the allowed constraints.",
  "evidence_id": null
}
```

---

## 6. Extended security.yaml Schema

For MVP, the existing `security.yaml` format is compiled as-is. Post-MVP, the schema can be extended:

```yaml
# --- Existing fields (compiled to Rego as-is) ---
dangerous_flags: [...]
tool_allowed_flags: {...}
tool_blocked_flags: {...}
output_flags: [...]
denied_binaries: [...]

# --- New fields (post-MVP extensions) ---
protected_rm_dirs:
  - "/cases"
  - "/evidence"

blocked_input_dirs:
  - "/etc"
  - "/proc"
  - "/sys"
  - "/dev"
  - "/boot"

blocked_input_exceptions:
  - "~/.vhir/cases"
  - "~/.vhir/hayabusa-output"

blocked_output_dirs:
  - "/etc"
  - "/proc"
  - "/sys"
  - "/dev"
  - "/boot"
  - "/usr"
  - "/bin"
  - "/sbin"
  - "/lib"
  - "/var"
  - "/home"

shell_metacharacters:
  - ";"
  - "&&"
  - "||"
  - "`"
  - "$("
  - "${"

program_text_tools:
  - "awk"
  - "gawk"
  - "mawk"
  - "nawk"

custom_rules:
  - name: "block_recursive_delete"
    description: "Block rm -rf patterns"
    rego_code: |
      deny contains msg if {
        input.tool == "rm"
        some flag in input.flags
        flag in {"-rf", "-fr", "--recursive"}
        msg := "BLOCKED: recursive forced deletion is not permitted"
      }
```

---

## 7. Configuration

```yaml
# In gateway.yaml or case-level config
policy_engine:
  enabled: true
  opa_mode: "embedded"              # "embedded" (subprocess) | "server" (HTTP sidecar)
  security_yaml: "data/catalog/security.yaml"
  compiled_dir: "compiled/"
  compile_on_startup: true
  fallback_security_py: true        # Run security.py after OPA for MVP parity validation
  log_decisions: true

sandbox:
  enabled: true
  profile: "default"                # Profile name from packages/sandbox/profiles/
  bwrap_path: "/usr/bin/bwrap"      # Override if bwrap is elsewhere
  timeout: 600                      # Per-command timeout in seconds
  # Evidence and output paths are resolved from case context at runtime
```

---

## 8. Implementation Sequence

### Day 1: YAML→Rego Compiler + OPA Evaluation

| Block | Task | Deliverable |
|-------|------|-------------|
| Morning (2-3h) | Trace `run_command` → `security.py` in the fork. Map every `security.yaml` field to its consuming function. Identify the hook point. | Integration map. Clear function signatures. |
| Early afternoon (2h) | Create `packages/policy-engine/`. Build `schema.py` (Pydantic), `compiler.py` (YAML→data.json + Jinja2→.rego). Test with `opa eval`. | `python -m policy_engine.compiler compile security.yaml` produces valid .rego + data.json. |
| Late afternoon (2h) | Write Jinja2 templates for all policy categories. Write `parser.py` (tool call → OPA input doc). | Templates compile security.yaml into Rego covering all security.py cases. |
| Evening (2h) | Build `evaluator.py` (OPA subprocess). Wire into `run_command` before `security.py`. Structured MCP denial on deny, fallthrough on allow. | End-to-end: MCP call → compile → OPA eval → deny/allow with reasons. |

**Day 1 exit criteria:** `run_command("find /evidence -exec rm {} ;")` returns structured denial citing `-exec` blocked AND `;` metacharacter. `run_command("fls -r /evidence/disk.img")` passes OPA, passes security.py, executes. Both logged.

### Day 2: bwrap Sandbox

| Block | Task | Deliverable |
|-------|------|-------------|
| Morning (2-3h) | Install bwrap on SIFT/dev VM. Create `packages/sandbox/`. Write `bwrap.py` with `BwrapSandbox` class. Write `default.yaml` profile. Test manually: `bwrap --ro-bind /evidence /evidence -- ls /evidence` works, `bwrap --ro-bind /evidence /evidence -- touch /evidence/test` fails with EROFS. | Working bwrap wrapper that takes a tool + args and returns subprocess result. |
| Early afternoon (2h) | Wire `bwrap.py` into the `run_command` path. After OPA+security.py allow, check config. If sandbox enabled, wrap `subprocess.run()` with `sandbox.execute()`. | Config-driven sandbox. Tools execute inside bwrap namespaces. |
| Late afternoon (2h) | Integration testing with Claude Code. Run analysis on sample case data. Verify three scenarios: OPA allow → bwrap execute → output returned; OPA deny → structured feedback → self-correct; write attempt → EROFS at kernel. | Working end-to-end demo. |
| Evening (1-2h) | Polish audit logging (policy decisions + sandbox flags in audit trail). Write kernel-block demo script. | Demo-ready. |

**Day 2 exit criteria:** Claude Code → `run_command` → OPA evaluates compiled Rego → tool executes inside bwrap with evidence `:ro` → output returns with enrichment → audit trail captures policy decision + sandbox profile used.

---

## 9. Demo Script (5-minute video)

### Scenario 1: Clean Allow (30s)
Agent parses an MFT. OPA allows. bwrap wraps the execution — evidence read-only, network isolated. Output returns with forensic-knowledge enrichment. Show the bwrap flags in the audit log.

### Scenario 2: Policy Denial + Self-Correction (90s)
Agent tries `find -exec`. OPA returns TWO reasons: `-exec` blocked per `tool_blocked_flags`, `;` is a shell metacharacter. Agent reformulates with `-print`, retries, succeeds. Audit trail: denied → allowed.

### Scenario 3: Kernel-Level Evidence Protection (60s)
Demonstrate: even if OPA allowed a write to evidence, bwrap's `--ro-bind` blocks it at the kernel. Show EROFS error. Explain: this protection works regardless of LLM client, prompt engineering, or policy bugs. It's the namespace, not the application.

### Architecture Walkthrough (90s)
Show security.yaml (familiar). Show compiled .rego (generated). Show OPA returning structured decisions. Show the bwrap command that actually ran. Two layers: policy-as-code (OPA) + kernel isolation (bwrap).

### Why This Matters (30s)
Same pattern works beyond DFIR. Policy-as-code + kernel sandboxing for any agentic tool execution. Cloud IR, SOC automation, any domain where agents need governed access to system tools.

---

## 10. Submission Checklist

| # | Component | Status | Notes |
|---|-----------|--------|-------|
| 1 | Code Repository | ☐ | GitHub public, fork of AppliedIR/sift-mcp, MIT license |
| 2 | Demo Video (5 min) | ☐ | Three-scenario script above |
| 3 | Architecture Diagram | ☐ | YAML→Rego→OPA + bwrap pipeline |
| 4 | Written Project Description | ☐ | Devpost story format |
| 5 | Dataset Documentation | ☐ | Which case data, source, findings |
| 6 | Accuracy Report | ☐ | Policy decisions vs security.py parity, evidence integrity |
| 7 | Try-It-Out Instructions | ☐ | README: fork, install bwrap+OPA, compile policies, run |
| 8 | Agent Execution Logs | ☐ | AIIR audit trail JSONL with policy decisions + sandbox flags |

---

## 11. Judging Criteria Alignment

| Criteria | How This Submission Addresses It |
|----------|--------------------------------|
| **Autonomous Execution Quality (tiebreaker)** | Agent receives structured denials with ALL violation reasons, enabling effective self-correction. OPA returns everything wrong at once. |
| **IR Accuracy** | Forensic-knowledge enrichment preserved. Policy engine prevents evidence-destroying commands. bwrap provides kernel-enforced evidence integrity. |
| **Breadth and Depth of Analysis** | Depth of enforcement architecture. Full parity with security.py plus composability. All 200+ SIFT tools available (no subset — bwrap wraps the host tools). |
| **Constraint Implementation** | Primary strength. ALL guardrails are architectural: compiled Rego evaluated by OPA + kernel-enforced read-only mounts via bwrap namespaces. Zero prompt-based restrictions. YAML authoring means practitioners can extend without learning Rego. |
| **Audit Trail Quality** | Every policy decision logged with all deny reasons. Every sandboxed execution logged with the bwrap flags used. Full trace from intent → policy → sandbox → execution → output. |
| **Usability and Documentation** | Practitioners edit the same YAML they already know. bwrap is a single `apt-get install`. Configuration is one YAML toggle. |

---

## 12. Post-MVP / Upstream PR Roadmap

1. **Remove security.py fallback** — Once OPA parity validated, PR to replace Python enforcement
2. **Extended security.yaml schema** — Move hardcoded paths into YAML
3. **`custom` rule type** — Raw Rego escape hatch for complex policies
4. **Per-case policy overrides** — Layer case-specific YAML on top of defaults
5. **seccomp-bpf profiles** — bwrap supports `--seccomp` for syscall filtering
6. **Sandbox profile per tool category** — Different profiles for memory analysis vs disk vs network
7. **OPA bundle hot-reload** — Recompile without restarting MCP server
8. **Claude Code PreToolUse hook** — Route all bash through MCP policy server
9. **Policy management MCP tools** — `list_policies`, `check_policy` (dry-run)
10. **Parity test harness** — Automated comparison of OPA vs security.py decisions across edge cases

---

## 13. Open Questions

- **OPA binary vs subprocess latency:** Benchmark `opa eval` via subprocess. If >200ms, run OPA as persistent server on localhost.
- **bwrap on SIFT VM:** Verify bwrap is available or installable on the current SIFT Workstation image. It should be (Ubuntu 22.04), but confirm.
- ~~**Dotnet tools in bwrap:**~~ **RESOLVED by 2026-05-31 audit.** Zimmerman tools are `/bin/bash` wrappers → `dotnet /opt/zimmermantools/*.dll`. `/usr` (dotnet 9 runtime) + `/opt` in the default profile cover them. They run clean with `HOME` unbound and no `DOTNET_*` env — MFTECmd produced a 77 MB CSV inside the sandbox. **No `--setenv` or extra mounts needed.** (A minimal `env:` hygiene block was added regardless: `HOME=/tmp`, telemetry opt-out.)
- ~~**Python tools in bwrap:**~~ **RESOLVED.** Volatility 3 (`/usr/local/bin/vol` + `/opt/volatility3` venv) runs `windows.pslist` clean under the default profile with a pre-staged symbol cache. `/usr` + `/opt` cover it.
- **One real gap found:** the default profile needed `/etc` (read-only) added — `foremost` loads `/etc/foremost.conf` and `bulk_extractor` SIGSEGVs without it. Fixed. See `docs/bwrap-tool-audit-prompt.md` for the full matrix.
- **security.py parity validation:** How do we prove compiled Rego produces identical decisions to security.py? Build a test harness that runs both against the same inputs and compares.
- **Steve Anson coordination:** Slack message before starting. Pitch: "We're adding OPA policy evaluation compiled from your existing YAML format, plus bwrap sandboxing at the MCP execution layer — practitioners keep editing YAML, enforcement gets structured decisions and kernel isolation."
- **Sample case data:** Check hackathon resources for provided datasets.
