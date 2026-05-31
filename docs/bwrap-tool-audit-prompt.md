# SIFT Tool ↔ Sandbox Compatibility Audit

> **Audit results (2026-05-31).** This audit was run on the SIFT VM against real
> FOR508 evidence (win7-64-nfury E01 + win7-mem.raw) via `tools/bwrap_audit.py`,
> which drives the production `build_sandbox_prefix` path. Outcome: **21 PASS,
> 0 tools requiring `--setenv`, 1 real fix.**
>
> - **The dotnet/Zimmerman assumption was wrong.** MFTECmd, EvtxECmd,
>   AppCompatCacheParser, and bstrings all run clean under the default profile
>   with `HOME` inherited-but-unbound and no `DOTNET_*` env — MFTECmd produced a
>   77 MB CSV. dotnet 9's build of these tools does **not** need `$HOME/.dotnet`
>   or `DOTNET_CLI_HOME` writable. No `--setenv` was required by any installed tool.
> - **The one real gap:** the default profile didn't bind `/etc`. `foremost`
>   (loads `/etc/foremost.conf`) and `bulk_extractor` (SIGSEGV) both fail without
>   it; both pass with `/etc` read-only. Fix applied to `profiles/default.yaml`.
> - A minimal profile `env:` → `--setenv` hook was added anyway (hygiene:
>   `HOME=/tmp`, dotnet telemetry opt-out) and as the hardening hook for stricter
>   profiles — not because any tool needs it.
> - **N/A (not sandbox issues):** `mmls` (logical image, no partition table),
>   `exiftool` (doesn't parse `.evtx`). Untested: hayabusa/yara/plaso/regripper
>   are not installed on the VM.
>
> The methodology below is retained for re-running against a fuller toolset.

You are auditing every forensic tool on this SIFT Workstation to determine how it behaves inside the bubblewrap (bwrap) sandbox. The sandbox enforces read-only evidence mounts and network isolation, which can cause tools to fail silently or with cryptic errors when they need to write caches, download dependencies, or create temp files outside of `/tmp`.

## Your Goal

For each tool, produce a structured compatibility record documenting:
1. Whether it runs successfully inside the sandbox with default profile
2. What it tries to write and where (cache dirs, lock files, config, symbol downloads)
3. What it tries to access on the network and why
4. The minimum fix that makes it work without weakening evidence protection

## Current Sandbox Capabilities — Read This First

Before running the audit, understand exactly what the sandbox can and cannot do today. Proposed fixes MUST be actionable within these constraints unless explicitly flagged as requiring a code change.

### What `build_sandbox_prefix()` controls

The bwrap command prefix is assembled from two sources:

**1. Profile-derived (static, applies to all commands using this profile):**
- `read_only`: list of paths bound as `--ro-bind` (identity bind, same path inside and outside)
- `bind_tmp_rw`: if true, `--bind /tmp /tmp` (RW); if false, `--tmpfs /tmp` (ephemeral)
- `proc`: if true, `--proc /proc`
- `dev`: if "minimal", `--dev /dev` (null, zero, urandom only)
- `unshare`: list of namespaces to isolate (`net`, `pid`, `ipc`, optionally `uts`)
- `die_with_parent`, `new_session`: process lifecycle flags

**The profile has NO mechanism for:**
- Per-tool RW bind mounts (no `read_write` list or equivalent)
- Per-tool environment variables (no `--setenv` emission, no `--clearenv`)
- Per-tool seccomp profiles
- Per-tool capability grants

**2. Parsed-path-derived (dynamic, varies per command, constructed by `parser.py`):**
- `input_paths` → `--ro-bind` (evidence files, read-only, applied AFTER RW binds so they win)
- `output_paths` → `--bind` on the parent directory (RW, for tool output)
- `device_paths` → `--dev-bind-try` (best-effort, for disk forensics tools only)
- `case_dir` → `--bind` (RW, for the active case directory)

**Mount ordering matters:** RW binds (case dir, output parents, /tmp) are applied BEFORE RO binds (evidence, profile read_only list). bwrap's later-bind-wins semantics mean evidence nested inside a writable case directory stays read-only.

### What this means for fixes

There are exactly four types of actionable fixes today:

| Fix Type | How It Works | Example |
|----------|-------------|---------|
| **pre-prime** | Run the tool bare once to populate a cache, then the cache is available inside the sandbox via existing RO binds (profile `read_only` covers `/opt`, `/usr`, etc.) | vol3 symbol cache: prime into case dir, sandboxed run reads it |
| **profile-ro-add** | Add a path to the profile's `read_only` list so it's available inside the sandbox | Add `/usr/share/dotnet` if not already covered by `/usr` |
| **output-path** | The tool's output flag is recognized by `parser.py`'s `output_flags` list, so the output parent dir becomes a RW bind automatically | Tool writes `--csv /cases/CASE/out/report.csv` → parent `/cases/CASE/out` is RW |
| **cannot-sandbox** | The tool fundamentally needs privileges the sandbox drops (PTRACE, raw devices, network, writable system dirs). Document as a known limitation. | `mount`, `losetup`, `strace` |

**If a tool needs a writable path outside the case dir and /tmp** (e.g., `~/.cache`, `~/.local/share`, `~/.dotnet`), there is currently no profile-level or per-tool mechanism to provide it. Document this as a **code-change-required** finding with the specific path and reason. These findings will be used to design the `--setenv` and per-tool RW mount features.

### Environment variables

bwrap inherits the MCP server's environment as-is. There is no `--clearenv` and no `--setenv` in the prefix builder. If a tool needs `DOTNET_CLI_HOME=/tmp/dotnet` or `HOME=/tmp/fakehome`, that cannot be applied per-tool today — it would affect the entire server process.

**Do not propose env_adjustments as a fix.** Instead, document the env var the tool needs, what it controls, and flag it as `fix_type: code-change-required` with `code_change: "add --setenv support to bwrap.py for per-tool env"`. These findings will drive the implementation of `--setenv` support.

## Methodology

For each tool, run this sequence:

### Step 1: Bare run (no sandbox) — establish baseline
Run the tool against the test case data with its most common invocation pattern. Record exit code, output size, and elapsed time. This is the ground truth.

### Step 2: Sandboxed run — identify breakage
Run the same command through `run_command` with `SIFT_SANDBOX=1`. Compare exit code, output, and stderr against the baseline. Classify the result:
- **PASS**: identical or functionally equivalent output
- **DEGRADED**: runs but with warnings, missing enrichment, or reduced output
- **FAIL-SILENT**: exits 0 but output is empty, truncated, or wrong
- **FAIL-LOUD**: nonzero exit code or error message

### Step 3: Diagnose failures
For DEGRADED, FAIL-SILENT, or FAIL-LOUD results, determine root cause. **Run `strace` on the BARE command (outside the sandbox)** to see what files and sockets the tool touches:

```bash
strace -f -e trace=open,openat,connect,write <tool> <args> 2>strace.log
```

**strace cannot run inside the sandbox.** The `--unshare-pid` namespace and dropped capabilities block PTRACE. All strace diagnostics must be performed on bare (unsandboxed) runs. Use the strace output to identify what the tool tried to access, then determine whether the sandbox blocked it.

Common failure categories:
- **WRITE-CACHE**: tool tries to write a cache/database (e.g., vol3 symbol cache, yara compiled rules)
- **WRITE-CONFIG**: tool tries to write or update config files in home dir
- **WRITE-TEMP-NONSTANDARD**: tool needs writable temp outside /tmp (e.g., dotnet tools use ~/.local/share)
- **NETWORK**: tool tries to download something (symbols, signatures, updates)
- **PROC-SYS**: tool reads /proc or /sys entries not available in the sandbox (note: default profile mounts /proc, strict does not)
- **DEVICE**: tool needs /dev/ access beyond minimal (/dev/null, /dev/zero, /dev/urandom)
- **LIBRARY**: tool can't find shared libs, python modules, or dotnet runtime
- **PID-VISIBLE**: tool probes other processes (e.g., reads /proc/<pid>/) which --unshare-pid hides

### Step 4: Propose fix within current constraints

For each failure, determine if an actionable fix exists today:

**If WRITE-CACHE and the cache can be pre-primed:**
Document the prime command. After priming, the cache will be readable inside the sandbox if it lives under a path already in the profile's `read_only` list or in the case directory (which is RW). This is the preferred fix — no code changes needed.

**If WRITE-CACHE/WRITE-CONFIG/WRITE-TEMP-NONSTANDARD and the path is outside case dir and /tmp:**
This is a **code-change-required** finding. Document:
- The exact path the tool tries to write
- What it's writing (cache, config, temp data)
- Whether the write is essential for correct operation or just nice-to-have
- Whether redirecting via an env var (e.g., `HOME`, `XDG_CACHE_HOME`, `DOTNET_CLI_HOME`) would work IF `--setenv` were supported
- The specific env var and value that would fix it

**If NETWORK:**
Can the dependency be pre-fetched outside the sandbox? If so, document the pre-fetch command. If the tool fundamentally requires network for correct operation (unlikely for forensic analysis), mark as `cannot-sandbox`.

**If LIBRARY:**
Is the library path already covered by the profile's `read_only` list (`/usr`, `/lib`, `/lib64`, `/opt`)? If not, propose adding it to the profile's `read_only` list as a `profile-ro-add` fix.

**If DEVICE (beyond /dev/ minimal) or needs dropped capabilities:**
Mark as `cannot-sandbox`. Document the requirement.

### Step 5: Verify fix (when actionable)
For pre-prime and profile-ro-add fixes, re-run the sandboxed command with the fix applied. Confirm output matches baseline.

For code-change-required fixes, note `verified: false` and document what would need to be tested after the code change lands.

## Output Format

Write results to a YAML file at the case output directory. One entry per tool:

```yaml
tools:
  - name: vol3
    binary: /usr/local/bin/vol
    test_command: ["vol", "-s", "{symbols_dir}", "-f", "{evidence}", "windows.pslist"]
    baseline:
      exit_code: 0
      output_lines: 42
      elapsed_seconds: 4.2
    sandbox_result: FAIL-SILENT
    failure_category: [WRITE-CACHE, NETWORK]
    failure_detail: |
      vol3 attempts to download PDB symbols from Microsoft symbol server
      on first run, writing to ISF cache directory. --unshare-net blocks
      the download, --ro-bind /opt blocks the cache write. Tool exits 0
      but returns empty process list.
    fix:
      fix_type: pre-prime
      prime_command: "vol -s /cases/{case}/symbols -f {evidence} windows.pslist"
      prime_note: "Run once outside sandbox to populate symbol cache in case dir"
      profile_changes: []
      code_changes_needed: []
    verified: true
    sandbox_result_after_fix: PASS

  - name: MFTECmd
    binary: /opt/zimmerman/MFTECmd.dll
    test_command: ["dotnet", "/opt/zimmerman/MFTECmd.dll", "-f", "{mft_file}", "--csv", "{output_dir}"]
    baseline:
      exit_code: 0
      output_lines: 500
      elapsed_seconds: 2.1
    sandbox_result: FAIL-LOUD
    failure_category: [WRITE-TEMP-NONSTANDARD]
    failure_detail: |
      dotnet runtime attempts to write to ~/.local/share/dotnet/ and
      ~/.dotnet/ for telemetry and runtime cache. Both are under the
      home directory which has no RW bind in the sandbox.
    fix:
      fix_type: code-change-required
      prime_command: null
      prime_note: null
      profile_changes: []
      code_changes_needed:
        - description: "Add --setenv support to bwrap.py"
          detail: |
            DOTNET_CLI_HOME=/tmp/dotnet-home and DOTNET_CLI_TELEMETRY_OPTOUT=1
            would redirect dotnet's writable state to /tmp (which is RW in the
            sandbox). Requires build_sandbox_prefix() to accept and emit
            --setenv flags.
          env_vars:
            DOTNET_CLI_HOME: "/tmp/dotnet-home"
            DOTNET_CLI_TELEMETRY_OPTOUT: "1"
    verified: false
    sandbox_result_after_fix: null

  - name: strings
    binary: /usr/bin/strings
    test_command: ["strings", "{evidence}"]
    baseline:
      exit_code: 0
      output_lines: 15000
      elapsed_seconds: 0.8
    sandbox_result: PASS
    failure_category: []
    failure_detail: ""
    fix: null
    verified: true
```

## Tool Inventory

Work through tools in this priority order (most commonly used in IR first):

### Tier 1 — Core IR tools (test all of these)
- `vol` / `vol3` (Volatility 3) — memory analysis
- `fls`, `icat`, `mmls`, `img_stat`, `fsstat`, `ifind`, `istat`, `blkls`, `blkstat`, `tsk_recover`, `sorter` (Sleuth Kit) — disk forensics
- `AmcacheParser`, `PECmd`, `AppCompatCacheParser`, `RECmd`, `MFTECmd`, `EvtxECmd`, `JLECmd`, `LECmd`, `SBECmd`, `RBCmd`, `SrumECmd`, `SQLECmd`, `bstrings` (Zimmerman / dotnet tools) — **Expect WRITE-TEMP-NONSTANDARD failures from the dotnet runtime. These will likely all share the same root cause and code-change-required fix.**
- `hayabusa` — Windows event log analysis
- `yara` — pattern matching
- `log2timeline` / `psort` (Plaso) — timeline creation
- `foremost` — file carving

### Tier 2 — Analysis tools (test these next)
- `strings`, `grep`, `find`, `awk`, `sed`, `cut`, `sort`, `uniq`, `wc`, `head`, `tail`, `tr`, `diff`, `jq`, `zcat`, `zgrep` (coreutils / text processing)
- `file`, `stat`, `ls`, `cat` (inspection)
- `md5sum`, `sha1sum`, `sha256sum` (hashing)
- `xxd`, `hexdump`, `readelf`, `objdump` (binary inspection)
- `exiftool` — metadata extraction
- `ssdeep` — fuzzy hashing
- `binwalk` — firmware/embedded analysis

### Tier 3 — Network and specialized (test if time allows)
- `tshark`, `tcpdump` (network capture analysis)
- `bulk_extractor` — bulk data extraction
- `regripper` — Windows registry
- `dd` (disk imaging — read-only usage)
- `mount`, `losetup` (image mounting — these need capabilities the sandbox drops, expect `cannot-sandbox`)

## Key things to watch for

1. **Dotnet tools (Zimmerman suite)**: These run via `dotnet /path/to/Tool.dll`. They will almost certainly need `~/.dotnet` and/or `~/.local/share/dotnet` writable. The default profile's `read_only` list covers `/usr` and `/opt` which handles the runtime binaries, but the dotnet runtime also wants to write telemetry and cache data to the home directory. This is a code-change-required finding — document the env vars that would fix it (`DOTNET_CLI_HOME`, `DOTNET_CLI_TELEMETRY_OPTOUT`) so the `--setenv` implementation knows what to support. **Test one Zimmerman tool first (MFTECmd is a good choice) and confirm the root cause, then batch-note the rest as sharing the same fix rather than running each individually if they all fail identically.**

2. **Python tools (vol3, plaso, log2timeline)**: May need virtualenv paths readable. Check if `/opt/volatility3` venv and Plaso paths are covered by the default `/opt` ro-bind. Python may also try to write `.pyc` bytecode cache — this should fail silently and not affect operation, but verify.

3. **Tools that compile/cache on first run**: yara may compile rules, vol3 downloads symbols, plaso builds databases. Identify which can be pre-primed vs. which need runtime write access.

4. **Tools that read /proc**: Some tools read `/proc/meminfo`, `/proc/cpuinfo`, etc. The default profile mounts `/proc` but strict does not. Note any tools that need it. Also note that `--unshare-pid` means tools cannot see host processes via `/proc/<pid>/` — this is usually fine for forensic tools but document any that probe running processes.

5. **Large output tools**: Tools that produce gigabytes of output (bulk_extractor, foremost, tsk_recover) need adequate RW space. Verify the case output dir binding provides sufficient room.

6. **Mount/losetup**: These tools inherently need capabilities the sandbox drops (CAP_SYS_ADMIN for mount, loop device access). They cannot run inside bwrap. Document as `cannot-sandbox` with the recommendation to run them bare to prepare evidence (mount disk images, set up loop devices), then switch to sandboxed analysis for the tools that read the mounted evidence.

## Deliverables

1. **The YAML compatibility matrix** (written to case output dir as `sandbox-compatibility.yaml`)
2. **A summary table**: tool name, sandbox result, fix type (none / pre-prime / profile-ro-add / code-change-required / cannot-sandbox)
3. **Proposed updates to `default.yaml`**: any additional paths for the profile's `read_only` list discovered during the audit. This must be a valid profile that `load_profile("default")` can consume — same schema as the existing `packages/sift-mcp/src/sift_mcp/sandbox/profiles/default.yaml`.
4. **A `prime-case.sh` script** that runs all pre-prime commands for a new case (symbol caches, compiled rules, etc.) so practitioners can prep once and sandbox after
5. **A code-change summary**: consolidated list of all code-change-required findings, grouped by the feature they need (e.g., all dotnet tools needing `--setenv` grouped together). This drives the post-audit implementation work.

Start with Tier 1. Report findings as you go — don't wait until the end to write everything up.
