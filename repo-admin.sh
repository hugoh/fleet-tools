#!/usr/bin/env bash
# Thin dispatcher so repo_admin.py can be run as `./repo-admin.sh <command>`
# from the repo root, without `cd repo-admin` first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# vcs-versioning's jj backend ignores the per-package tag filter, so building
# the workspace packages in a colocated jj checkout picks a sibling's tag.
export SETUPTOOLS_SCM_DISABLE_JJ=1

exec uv run --project "$SCRIPT_DIR/repo-admin" "$SCRIPT_DIR/repo-admin/repo_admin.py" "$@"
