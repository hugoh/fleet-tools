# config/

The fleet config data (`pages-domains.yaml`, `forks-include.yaml`,
`branch-protection-exclude.yaml`, `secrets.enc.yaml`, `variables.yaml`,
`variables.enc.yaml`, `.sops.yaml`) is **not kept here** — it lives in a
separate repo and is pointed at with `REPO_ADMIN_CONFIG_DIR`, which a wrapper
in that repo exports before invoking this CLI.

`repo_admin.py` falls back to this directory when `REPO_ADMIN_CONFIG_DIR` is
unset, so a local `config/*.yaml` set still works for development.
