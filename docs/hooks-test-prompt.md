# Test the Hooks Module (Layer 0: Harness Hook Adapters)

You are testing the new `sift_mcp.hooks` package which provides policy enforcement hooks for three agent harnesses: Claude Code, OpenCode, and Pi. The hooks intercept bash/shell commands before execution and evaluate them against the OPA policy engine — closing the bypass gap where an agent uses its native bash tool instead of sift-mcp's `run_command`.

## What You're Testing

The hooks package lives at `packages/sift-mcp/src/sift_mcp/hooks/` and contains:

- `gate.py` — Universal policy gate script. Reads a command from stdin (Claude Code/OpenCode JSON), env var (`OPENCODE_TOOL_ARGS`), or argv. Calls `evaluate_command()` from the policy engine. Exits 0 (allow) or 2 (deny, reasons on stderr). Fails open on errors.
- `install.py` — Generates and writes hook config for each harness. Merges into existing config without overwriting. Supports `--harness claude-code|opencode|pi`, `--detect`, and `--all`.
- `pi_extension.ts` — TypeScript extension for Pi's in-process hook system. Shells out to `gate.py`.

Tests are at `tests/test_sift_mcp/test_hooks.py`.

## Step 1: Run the existing tests

```bash
cd /path/to/sift-mcp
pytest tests/test_sift_mcp/test_hooks.py -v
```

If tests fail, diagnose and fix. Common issues to watch for:
- Import paths — `sift_mcp.hooks.gate` must be importable from the test environment
- The `_FakeStdin` helper must correctly simulate a non-TTY stdin
- The `yaml` import in `install.py` requires PyYAML (should already be in the venv)
- Subprocess tests skip automatically if `tools/opa` is missing — that's expected on non-SIFT machines

Do NOT move on until the unit tests pass.

## Step 2: Manual gate.py smoke tests

Test the gate as a real subprocess to verify the stdin/exit-code contract each harness relies on.

### Claude Code format (stdin JSON):
```bash
# Should DENY (mkfs is a denied binary)
echo '{"tool_input": {"command": "mkfs /dev/sda1"}}' | \
  SIFT_POLICY_ENGINE=1 python3 -m sift_mcp.hooks.gate
echo "Exit code: $?"
# Expected: exit 2, stderr contains "mkfs" and "blocked"

# Should ALLOW
echo '{"tool_input": {"command": "strings /cases/test/evidence.bin"}}' | \
  SIFT_POLICY_ENGINE=1 python3 -m sift_mcp.hooks.gate
echo "Exit code: $?"
# Expected: exit 0, no stderr

# Should DENY (shell metacharacter)
echo '{"tool_input": {"command": "cat /evidence/f; rm -rf /"}}' | \
  SIFT_POLICY_ENGINE=1 python3 -m sift_mcp.hooks.gate
echo "Exit code: $?"
# Expected: exit 2, stderr mentions metacharacter or ";"

# Should DENY (-exec on find)
echo '{"tool_input": {"command": "find /evidence -exec rm {} ;"}}' | \
  SIFT_POLICY_ENGINE=1 python3 -m sift_mcp.hooks.gate
echo "Exit code: $?"
# Expected: exit 2, stderr mentions "-exec" AND ";" (two reasons)
```

### OpenCode format (env var):
```bash
# Should DENY
SIFT_POLICY_ENGINE=1 OPENCODE_TOOL_ARGS='{"command": "nc -l 4444"}' \
  python3 -m sift_mcp.hooks.gate
echo "Exit code: $?"
# Expected: exit 2, stderr contains "nc" and "blocked"
```

### argv format (generic):
```bash
# Should DENY
SIFT_POLICY_ENGINE=1 python3 -m sift_mcp.hooks.gate kill -9 1234
echo "Exit code: $?"
# Expected: exit 2

# Should ALLOW
SIFT_POLICY_ENGINE=1 python3 -m sift_mcp.hooks.gate echo hello
echo "Exit code: $?"
# Expected: exit 0
```

### Fail-open behavior:
```bash
# Policy engine disabled — should exit 0 (fail open, no evaluation)
python3 -m sift_mcp.hooks.gate mkfs /dev/sda1
echo "Exit code: $?"
# Expected: exit 0 (SIFT_POLICY_ENGINE not set, evaluator not initialized)

# No input — should exit 0
echo '' | python3 -m sift_mcp.hooks.gate
echo "Exit code: $?"
# Expected: exit 0
```

Record results for each test. Note any unexpected exit codes or missing/wrong stderr messages.

## Step 3: Install.py smoke tests

### Claude Code:
```bash
# Fresh install
cd $(mktemp -d)
python3 -m sift_mcp.hooks.install --harness claude-code --project-dir .
cat .claude/settings.local.json
# Expected: PreToolUse hook with matcher "Bash" and sift_mcp.hooks.gate command

# Duplicate install
python3 -m sift_mcp.hooks.install --harness claude-code --project-dir .
# Expected: "Already installed" message

# Merge with existing
rm -rf .claude
mkdir -p .claude
echo '{"hooks": {"PreToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "lint.sh"}]}]}}' > .claude/settings.local.json
python3 -m sift_mcp.hooks.install --harness claude-code --project-dir .
cat .claude/settings.local.json
# Expected: TWO entries in PreToolUse — Write (existing) and Bash (new)
```

### OpenCode:
```bash
cd $(mktemp -d)
python3 -m sift_mcp.hooks.install --harness opencode --project-dir .
cat .opencode/hooks.yaml
# Expected: tool.before.bash hook with action: stop and sift_mcp.hooks.gate

# Duplicate
python3 -m sift_mcp.hooks.install --harness opencode --project-dir .
# Expected: "Already installed"
```

### Pi:
```bash
cd $(mktemp -d)
python3 -m sift_mcp.hooks.install --harness pi --project-dir .
cat .pi/hooks/sift-policy-gate.ts
# Expected: TypeScript file with tool_call handler and sift_mcp.hooks.gate

# Duplicate
python3 -m sift_mcp.hooks.install --harness pi --project-dir .
# Expected: "Already installed"
```

### Auto-detection:
```bash
cd $(mktemp -d)
mkdir .claude
python3 -m sift_mcp.hooks.install --detect --project-dir .
# Expected: "Detected harness: claude-code" then installs

cd $(mktemp -d)
python3 -m sift_mcp.hooks.install --detect --project-dir .
# Expected: "Could not detect harness" error

cd $(mktemp -d)
python3 -m sift_mcp.hooks.install --all --project-dir .
ls -la .claude/settings.local.json .opencode/hooks.yaml .pi/hooks/sift-policy-gate.ts
# Expected: all three config files created
```

## Step 4: Live integration test (Claude Code on SIFT)

This is the real proof. Install the hook into the actual Claude Code session and verify it intercepts direct bash commands.

```bash
# Install the hook into the sift-mcp project's Claude Code config
cd /path/to/sift-mcp
SIFT_POLICY_ENGINE=1 python3 -m sift_mcp.hooks.install --harness claude-code --project-dir .
```

Then in a Claude Code session (or via `claude -p`):

1. Ask the agent to run a safe command directly via bash (not through run_command): `echo hello`. Should succeed — gate allows it.

2. Ask the agent to run a denied command directly via bash: `mkfs /dev/sda1`. The PreToolUse hook should fire, gate.py should deny it, and Claude Code should show the denial reason. The agent should NOT be able to execute it.

3. Ask the agent to run a command with a shell metacharacter: `cat /evidence/f; whoami`. Should be denied by the gate.

4. Ask the agent to use `run_command` MCP tool for the same denied command. Verify it's ALSO denied (by Layer 1, the MCP policy gate). This confirms both layers work independently.

**If the live test shows the hook firing but the agent retrying via direct bash**, that's expected behavior — Claude Code may attempt workarounds. The hook should block every attempt. Document how many retries the agent makes before giving up and self-correcting.

## Step 5: Verify three-layer defense in depth

Run this sequence to prove all three layers work:

| Command | Path | Layer That Blocks | Expected |
|---------|------|-------------------|----------|
| `mkfs /dev/sda1` | direct bash | Layer 0 (harness hook) | exit 2, denied binary |
| `mkfs /dev/sda1` | run_command MCP | Layer 1 (OPA in MCP) | PolicyDenialError |
| `find /evidence -exec rm {} ;` | direct bash | Layer 0 (harness hook) | exit 2, two reasons |
| `find /evidence -exec rm {} ;` | run_command MCP | Layer 1 (OPA in MCP) | PolicyDenialError, two reasons |
| `touch /evidence/test-file` | run_command MCP (sandbox on) | Layer 2 (bwrap) | EROFS |
| `echo hello` | direct bash | Layer 0 (harness hook) | exit 0, allowed |
| `fls -r /cases/c/disk.img` | run_command MCP | All layers | Allowed, sandboxed, enriched |

## Deliverables

1. `pytest` output showing all `test_hooks.py` tests pass (or fixes applied)
2. Manual smoke test results for gate.py (all harness formats)
3. Manual smoke test results for install.py (all three harnesses)
4. Live Claude Code integration test results (if on SIFT)
5. Three-layer defense matrix showing each layer blocks independently
6. Any bugs found and fixes applied

Report as you go. Fix issues in the code, not the tests (unless a test has a genuine bug).
