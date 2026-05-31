# Task 2 — SIFT end-to-end test (handoff for a clean session)

Goal: prove the full enforcement pipeline on the **real SIFT Workstation** with
**real forensic tools**, end-to-end through `run_command` (not bare `bwrap`).
This is PRD §10 deliverable: the three demo scenarios + the "Agent Execution
Logs" audit JSONL.

---

## 0. What's already done (don't rebuild)

Branch `feat/policy-engine-opa` (off `main`, **not pushed/merged**). Two
enforcement layers + parity harness are built, tested, committed. Recent log:

- `edd633c` docs: README "Find Evil!" enforcement-layers section
- `b81fe49` config-wiring: gateway.yaml policy_engine/sandbox sections (PRD §7)
- `1587e8d` parity: harness proving OPA matches security.py
- `cdbadda` sandbox: Layer 2 — bubblewrap kernel isolation
- `d362ea2` policy-engine: Layer 1 — YAML→Rego compiler + OPA evaluation

Both layers are **off in code by default**, enabled via env / gateway config.

- **Layer 1 (OPA):** `SIFT_POLICY_ENGINE=1`, `SIFT_OPA_PATH`, `SIFT_SECURITY_YAML`
- **Layer 2 (bwrap):** `SIFT_SANDBOX=1`, `SIFT_SANDBOX_PROFILE` (default `default`),
  `SIFT_BWRAP_PATH`
- Config read fresh each call: `packages/sift-mcp/src/sift_mcp/config.py`
  (`SiftConfig.from_env`).
- Gateway translates top-level `policy_engine:` / `sandbox:` sections in
  `gateway.yaml` → these env vars on the sift-mcp backend
  (`packages/sift-gateway/src/sift_gateway/config.py: apply_security_layers`).
  Example: `config/gateway.yaml.example` (policy ON, sandbox commented).

---

## 1. SIFT VM environment (verified facts)

- **SSH:** `sansforensics@192.168.8.129` — key auth works non-interactively,
  **passwordless sudo**.
- **OS:** Ubuntu 24.04.4 (kernel 6.8). *Not* 22.04 (PRD assumed 22.04).
- **bwrap:** 0.9.0 at `/usr/bin/bwrap` (non-setuid). ⚠️ Older than the WSL dev
  box's 0.11.2 — see gotchas.
- **OPA:** NOT installed. Copy the repo's `./tools/opa` (v1.17.0, ~79 MB,
  untracked) over.
- **AppArmor userns fix:** ALREADY installed at `/etc/apparmor.d/bwrap`
  (persists across reboot). This is the profile granting `userns` to
  `/usr/bin/bwrap` — Ubuntu 24.04 sets
  `kernel.apparmor_restrict_unprivileged_userns=1`, which otherwise makes bwrap
  fail with "setting up uid map: Permission denied". If sandbox tests fail with
  a userns/clone error, re-verify:
  ```bash
  bwrap --ro-bind / / --unshare-net -- /bin/true   # should exit 0
  sudo apparmor_parser -r /etc/apparmor.d/bwrap     # reload if needed
  ```
- **Paths:** `/cases` exists. `/evidence` and `~/.vhir` do NOT exist — wire
  evidence/output mounts from real case context, not the PRD's hardcoded
  `/evidence`.
- **Repo:** not yet copied to SIFT.

### Validated sandbox mounts (default profile runs real tools)

Read-only `/usr` + `/opt` covers the forensic runtimes — no per-tool special
casing:
- dotnet runtime: `/usr/lib/dotnet` (PRD wrongly guessed `/usr/share/dotnet`).
- Zimmerman tools: `.dll`s in `/opt/zimmermantools`, run via `/usr/bin/dotnet`.
- Volatility 3: `vol` at `/usr/local/bin/vol`, venv at `/opt/volatility3`.
- Sleuth Kit (`fls` etc.): standard, under `/usr`.

Proven-working bare-bwrap flag set (already smoke-tested for `vol --help`,
`dotnet …AmcacheParser.dll`, `fls -V`):
```
--ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /sbin /sbin \
--ro-bind /lib /lib --ro-bind /lib64 /lib64 --ro-bind /opt /opt \
--proc /proc --dev /dev --tmpfs /tmp \
--unshare-net --unshare-pid --unshare-ipc --die-with-parent --new-session
```
NOTE: that was bare bwrap. Task 2 must prove these tools run **through
`run_command`** with the sandbox layer, which is only smoke-tested so far.

---

## 2. Setup steps on SIFT

```bash
# From the dev box: copy the working tree + opa to SIFT
rsync -a --exclude .venv --exclude .git /home/jg/git/sift-mcp/ \
  sansforensics@192.168.8.129:~/sift-mcp/
scp /home/jg/git/sift-mcp/tools/opa sansforensics@192.168.8.129:~/sift-mcp/tools/opa
# (or: git clone the branch on SIFT, then scp tools/opa separately)

# On SIFT: runtime
cd ~/sift-mcp
uv venv --python 3.12 .venv && . .venv/bin/activate
uv pip install -e packages/sift-common -e packages/forensic-knowledge \
  -e packages/sift-mcp -e packages/sift-gateway pytest pytest-asyncio jinja2
# (if uv missing: python3.12 -m venv .venv; pip install -e ... )

# Verify imports
python -c "import sift_mcp, sift_gateway, sift_common; print('imports OK')"
chmod +x tools/opa && ./tools/opa version
```

### Create a real case + sample evidence

`/evidence` does not exist; use a case dir under `/cases` (or `~`). Minimal:
```bash
CASE=/cases/e2e-test           # or ~/e2e-test
mkdir -p "$CASE/evidence" "$CASE/out"
printf 'case_id: e2e-test\n' > "$CASE/CASE.yaml"
# Drop a small sample artifact (EVTX / MFT / a tiny memory image). For a quick
# allow-path smoke without a memory image, fls/mmls on a small raw disk image,
# or a Zimmerman tool on a sample registry hive, also works.
export VHIR_CASE_DIR="$CASE"
# export VHIR_AUDIT_DIR=... if the audit writer needs an explicit dir
```

### Enable both layers (no manual exports if using the gateway)

Either set env directly:
```bash
export SIFT_POLICY_ENGINE=1
export SIFT_OPA_PATH=$PWD/tools/opa
export SIFT_SANDBOX=1
export SIFT_SANDBOX_PROFILE=default
```
…or use `gateway.yaml` (preferred — proves Task 1 wiring): copy
`config/gateway.yaml.example` to `gateway.yaml`, keep `policy_engine.enabled:
true`, and **uncomment the `sandbox:` block** (enabled true, profile default).
Set `opa_path` to `./tools/opa`. Launch sift-mcp via the gateway and confirm the
backend subprocess receives the `SIFT_*` env (Task 1's `apply_security_layers`).

---

## 3. The three scenarios to prove (acceptance)

Run these **through `run_command`** (via the gateway / an MCP client, or a small
Python harness that calls the sift-mcp executor directly), not as bare bwrap.

1. **Allow** — tool runs sandboxed, output enriched, audit logs sandbox flags:
   ```
   run_command("vol3 -f <CASE>/evidence/<image> windows.pslist")
   ```
   (or a Zimmerman/Sleuth Kit command if no memory image). Expect: success,
   enriched MCP envelope, and the audit JSONL entry shows `sandbox_profile`
   + the bwrap `sandbox_args` (the actual flags used).

2. **Policy deny (Layer 1)** — structured denial with all reasons:
   ```
   run_command("find <CASE>/evidence -exec rm {} \\;")
   ```
   Expect: a structured `policy_denial` envelope citing **both** `-exec`
   blocked on `find` (tool_blocked_flags) **and** the `;` shell metacharacter —
   not an opaque exception. Agent can self-correct.

3. **Kernel block (Layer 2)** — EROFS even if policy allowed it:
   ```
   run_command("touch <CASE>/evidence/proof")   # or a tool that writes evidence
   ```
   Expect: kernel rejects the write with **EROFS** because evidence is bound
   read-only — regardless of the policy decision.

**Capture the audit JSONL** produced across these runs — that's the PRD §10
"Agent Execution Logs" deliverable (policy decision + sandbox flags per call).

### Also run the parity harness on SIFT (sanity)
```bash
SIFT_OPA_PATH=$PWD/tools/opa python -m sift_mcp.policy.parity --fuzz 1000
# expect 100% parity, 0 divergent
```

---

## 4. GOTCHAS (check these first)

- **bwrap 0.9.0 vs the flags we emit.** The dev box has 0.11.2; SIFT has 0.9.0.
  Inspect the exact flags emitted by `packages/sift-mcp/src/sift_mcp/sandbox/bwrap.py`
  and cross-check against `bwrap --help` on SIFT. **Especially `--dev-bind-try`**
  (used for `device_paths`): if unsupported on 0.9.0, fall back to `--dev-bind`
  or skip device binds. Also confirm `--new-session`, `--die-with-parent`,
  `--unshare-*`, `--ro-bind`/`--bind`, `--proc`, `--dev`, `--tmpfs` are all
  accepted by 0.9.0 (they should be, but verify).
- **`/evidence` is not a real path on SIFT.** The profile must mount the real
  case evidence dir → a read-only path the tool sees. Confirm the executor
  resolves evidence/output mounts from case context, and that the profile's
  `if Path(resolved).exists()` guard no-ops missing mounts (so the same profile
  is harmless on the dev box).
- **dotnet/python tools sandboxed through `run_command`.** Only bare-bwrap
  smoke-tested so far. Volatility 3 needs its venv (`/opt/volatility3`) and
  Python under `/usr` — both covered by `/usr` + `/opt` ro binds, but verify the
  full `run_command` path actually works, not just `vol --help`.
- **Audit dir.** `~/.vhir` doesn't exist; make sure the audit writer has a
  writable target (set `VHIR_AUDIT_DIR` or equivalent if needed).

---

## 5. Known pre-existing test failures (NOT regressions)

When running `python -m pytest tests/test_sift_mcp/ -q`:
- `test_executor.py::TestAutoSave::test_auto_save_when_exceeds_budget`
- `test_executor.py::TestSaveOutputBlockedPrefixes::test_save_outside_case_dir_blocked`
- `test_instructions.py::TestServerInstructionsWired::test_forensic_mcp_server_has_instructions`
  (errors only because `forensic_mcp`/`case_mcp` aren't installed in the minimal venv)

Gateway suite (`tests/test_sift_gateway/`) is fully green (123 passed).

---

## 6. CLI reference

```bash
# Compile security.yaml → Rego + data.json
python -m sift_mcp.policy.compiler compile <security.yaml> -o compiled/

# Parity OPA vs security.py (writes a markdown report)
python -m sift_mcp.policy.parity --fuzz 3000 --out docs/parity-report.md
```

Sandbox profiles: `packages/sift-mcp/src/sift_mcp/sandbox/profiles/`
- `default.yaml` (name `default`) — evidence read-only, network isolated.
- `strict.yaml` (name `strict`) — maximum isolation, minimal fs, no /proc.

---

## 7. Definition of done

- [ ] Tree + opa on SIFT, venv built, imports OK, `opa version` works.
- [ ] Both layers enabled via `gateway.yaml` (proves Task 1 wiring) with no
      manual env exports.
- [ ] Scenario 1 (allow): real tool runs sandboxed via `run_command`, enriched
      output, audit logs sandbox_profile + bwrap flags.
- [ ] Scenario 2 (deny): structured `policy_denial` with all reasons.
- [ ] Scenario 3 (kernel block): EROFS on evidence write.
- [ ] Audit JSONL captured (the §10 deliverable).
- [ ] Parity harness re-run on SIFT (100%).
- [ ] bwrap 0.9.0 flag compatibility confirmed/patched.
- [ ] Update the `hackathon-build-plan` memory; commit any SIFT-compat fixes on
      `feat/policy-engine-opa`.

Remaining after Task 2: demo video + Devpost writeup.
