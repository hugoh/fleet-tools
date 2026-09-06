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

```text
uv sync
./repo-admin.sh sync              # merge + protection + security, fleet-wide
./repo-admin.sh repo scaffold ../new-repo --release --tests python
```

See [`repo-admin/README.md`](repo-admin/README.md) for the full command set and
[`docs/repo-setup.md`](docs/repo-setup.md) for the scaffold workflow.

## Releases

- `asyncgh`, `reconcilekit`, `hugoh-repokit` — release-please (one aggregated
  PR, per-component tags `<pkg>-vX.Y.Z`); merging it builds and publishes to
  PyPI via trusted publishing.
- `repo-admin` — not published; run it from a checkout.
