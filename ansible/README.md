# SIFT VM provisioning

One playbook turns a fresh SIFT Workstation OVA import into a working sift-mcp
execution target: root LV grown to the full disk, bwrap userns AppArmor fix,
repos synced, OPA installed to `/usr/local/bin`, venv built, `/cases`
scaffolded, enforcement probes run.

Manual procedure + rationale: [docs/sift-vm-setup.md](../docs/sift-vm-setup.md).

## Prereqs

- `ansible` (full package — uses `community.general.lvol` and
  `ansible.posix.synchronize`, not bundled with bare ansible-core)
- SSH key auth to the box: `ssh-copy-id sansforensics@<vm-ip>` (OVA default
  password: `forensics`)
- `sift-mcp` and `Valhuntir` checkouts on the controller (paths configurable
  via `sift_mcp_src` / `valhuntir_src`, default `~/git/...`)

## Run

```sh
cp inventory.example.ini inventory.ini   # edit the IP
ansible-playbook -i inventory.ini sift-provision.yml

# Provision + create/activate a case + run both enforcement probes:
ansible-playbook -i inventory.ini sift-provision.yml -e vhir_case_id=508-intrusion
```

Idempotent — safe to re-run after every repo change to push code
(`synchronize` + `uv pip install` are the only tasks that will report changed).

## What it does NOT do

- Copy evidence (tens of GB — do that with rsync directly)
- Register evidence with `vhir evidence register`
- Start the gateway
