# fleet-tools

The toolkit behind hugoh's repo fleet: the `repo-admin` CLI that bulk-applies
account-wide repo settings, the scaffold templates it renders new repos from,
and the three Python packages that sit underneath it — published to PyPI so
other repos ([`hugoh/digest-action`](https://github.com/hugoh/digest-action))
can share them.

The reusable GitHub Actions and workflows those repos call in CI live
separately, in [`hugoh/gh-workflows`](https://github.com/hugoh/gh-workflows).

## Contents

- [`repo-admin/`](repo-admin/README.md) — bulk repo settings + activity CLI,
  and [`repo-admin/templates/`](repo-admin/templates/README.md), the scaffold
  sources for new fleet repos
- [`asyncgh/`](asyncgh/README.md) — async GitHub REST/GraphQL transport
  ([PyPI](https://pypi.org/project/asyncgh/))
- [`reconcilekit/`](reconcilekit/README.md) — stateless fetch-diff-apply
  reconcile kernel ([PyPI](https://pypi.org/project/reconcilekit/))
- [`repokit/`](repokit/README.md) — repo listing/filtering + CLI plumbing,
  published as
  [`hugoh-repokit`](https://pypi.org/project/hugoh-repokit/)
- [`docs/repo-setup.md`](docs/repo-setup.md) — what every fleet repo is
  expected to have, and how to scaffold one

## Layout

A single `uv` workspace (`repo-admin`, `asyncgh`, `reconcilekit`, `repokit`).
`mise.toml` and `hk.pkl` are the fleet's **canonical** toolchain and lint
config — `repo scaffold` reads the tool versions straight out of them, so
there is one source of truth and no template drift.

## Usage

The fleet config data lives in a separate repo; drive `repo-admin` from the
wrapper there (it exports `REPO_ADMIN_CONFIG_DIR` and calls into this
checkout). For a config-free command, run the module directly:

```text
uv sync
cd repo-admin
uv run repo_admin.py repos list
uv run repo_admin.py repo scaffold ~/Code/new-repo --release --tests python
```

See [`repo-admin/README.md`](repo-admin/README.md) for the full command set and
[`docs/repo-setup.md`](docs/repo-setup.md) for the scaffold workflow.

## Releases

- `asyncgh`, `reconcilekit`, `hugoh-repokit` — no PR. Every push to `main` runs
  `cog bump --auto` (cocogitto, monorepo mode via `cog.toml`): each package
  whose files changed since its last tag gets a new `<pkg>-vX.Y.Z` tag from its
  Conventional Commits, plus a GitHub release. The version lives only in the
  tag — `hatch-vcs` derives it at build time — so nothing lands back on `main`.
  Each tag fires that package's `release-<pkg>.yml`, which builds and publishes
  to PyPI via trusted publishing.
- Breaking changes on a `0.x` package bump the minor, not `1.0.0`; reach
  `1.0.0` deliberately with `cog bump --package <pkg> --version 1.0.0`, then
  push the tag.
- `repo-admin` — not published; run it from a checkout.
