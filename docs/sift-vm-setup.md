# Fresh SIFT VM bring-up

Provisioning a brand-new SIFT Workstation VM (tested against `sift-2026-04-22.ova`,
Ubuntu 24.04.4, kernel 6.8) as a sift-mcp execution target. Total time: ~15 minutes
plus evidence transfer.

The whole procedure is automated in [`ansible/sift-provision.yml`](../ansible/README.md);
this document is the manual reference and explains *why* each step exists.

## What the OVA ships with

| Item | State |
|---|---|
| User | `sansforensics`, passwordless sudo (NOPASSwd, works non-interactively over SSH) |
| bubblewrap | 0.9.0 at `/usr/bin/bwrap`, **non-setuid** |
| Python | 3.12.3 |
| Disk | ~488 GB virtual disk, but root LV is only **100 GB** — the rest sits unallocated in the VG |
| OPA | not installed (the repo carries `tools/opa`, v1.17.0) |
| uv | not installed |

## 1. SSH key auth

```sh
ssh-copy-id sansforensics@<vm-ip>     # default password: forensics
ssh -o BatchMode=yes sansforensics@<vm-ip> 'sudo -n true && echo SUDO_OK'
```

## 2. Grow the root filesystem

The OVA leaves ~386 GB of the VG unallocated. Evidence sets won't fit in the
default 100 GB root.

```sh
sudo lvextend -l +100%FREE --resizefs /dev/ubuntu-vg/ubuntu-lv
df -h /        # expect ~479 GB
```

## 3. bwrap AppArmor userns fix

Ubuntu 24.04 sets `kernel.apparmor_restrict_unprivileged_userns=1`, so
unprivileged bwrap fails with `setting up uid map: Permission denied`. The
scoped fix (instead of flipping the system-wide sysctl) is an AppArmor profile
granting `userns` to the bwrap binary only:

```sh
sudo tee /etc/apparmor.d/bwrap > /dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,

  # Site-specific additions and overrides. See local/README for details.
  include if exists <local/bwrap>
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/bwrap
```

Verify (must print `BWRAP_OK`):

```sh
bwrap --ro-bind / / --unshare-net --unshare-user true && echo BWRAP_OK
```

The profile persists across reboots via the apparmor service.

## 4. Sync the repos

From the dev machine (`vhir-cli` lives in the separate Valhuntir repo and
`case-mcp`/`report-mcp` depend on it):

```sh
rsync -a --exclude .venv --exclude __pycache__ --exclude '*.pyc' \
    ~/git/sift-mcp/  sansforensics@<vm-ip>:sift-mcp/
rsync -a --exclude .venv --exclude __pycache__ --exclude '*.pyc' \
    ~/git/Valhuntir/ sansforensics@<vm-ip>:Valhuntir/
```

The OPA binary rides along at `~/sift-mcp/tools/opa` (gitignored but present in
a working tree that has run the e2e suite). Install it on PATH so the policy
evaluator finds it without `SIFT_OPA_PATH`:

```sh
sudo install -o root -g root -m 0755 ~/sift-mcp/tools/opa /usr/local/bin/opa
opa version    # expect 1.17.0
```

## 5. Python environment

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh    # installs to ~/.local/bin/uv
cd ~/sift-mcp
~/.local/bin/uv venv .venv --python python3.12
~/.local/bin/uv pip install --python .venv/bin/python \
    -e ~/Valhuntir \
    -e packages/sift-common \
    -e packages/forensic-knowledge \
    -e packages/sift-mcp \
    -e packages/sift-gateway \
    -e packages/case-mcp \
    -e packages/forensic-mcp \
    -e packages/report-mcp \
    pytest pytest-asyncio
```

Installing all editables in one command lets uv resolve the intra-repo
dependencies (`sift-common`, `forensic-knowledge`, `vhir-cli`) from the local
trees instead of trying PyPI.

Smoke test:

```sh
.venv/bin/python -c 'import sift_mcp, sift_gateway, case_mcp, forensic_mcp, report_mcp, vhir_cli'
```

## 6. Case scaffolding

```sh
sudo mkdir -p /cases && sudo chown sansforensics:root /cases && sudo chmod 775 /cases
export VHIR_CASES_DIR=/cases VHIR_EXAMINER=<examiner>
~/sift-mcp/.venv/bin/vhir case init <case-name> --case-id <case-id>
~/sift-mcp/.venv/bin/vhir case activate <case-id>
```

Copy evidence into `/cases/<case-id>/evidence/` and register each file with
`vhir evidence register <file>`.

## 7. Verify the enforcement layers

No evidence needed for the first two probes:

```sh
cd ~/sift-mcp
# Layer 1 — OPA policy: allow / structured deny / pass-through
VHIR_CASE_DIR=/cases/<case-id> SIFT_POLICY_ENGINE=1 SIFT_OPA_PATH=$HOME/sift-mcp/tools/opa \
    .venv/bin/python tools/e2e_policy_probe.py

# Layer 2 — bwrap sandbox: EROFS on evidence writes
VHIR_CASE_DIR=/cases/<case-id> SIFT_SANDBOX=1 \
    .venv/bin/python tools/e2e_sandbox_probe.py
```

The full three-layer proof (`tools/e2e_defense_matrix.py`) additionally needs a
real E01 at `$VHIR_CASE_DIR/evidence/win7-64-nfury-c-drive.E01`.

## Gotchas

- **bwrap 0.9.0**: the OVA's bubblewrap predates some newer flags; the flag set
  in `sift_mcp.sandbox.bwrap` is pinned to what 0.9.0 supports.
- **No pip in the venv**: uv-created venvs don't bundle pip. Always install via
  `~/.local/bin/uv pip install --python ~/sift-mcp/.venv/bin/python …`.
- **The VM is disposable.** Anything not in this doc / the playbook that you do
  by hand on the box will be lost on the next re-import. Fold it back in.
