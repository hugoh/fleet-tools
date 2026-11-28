"""mise must keep vcs-versioning off its jj backend.

In a jj checkout that backend ignores the per-package tag filter, so
`uv sync` picks a sibling package's tag and fails.

https://setuptools-scm.readthedocs.io/latest/usage/#jujutsu-jj-repositories
"""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_mise_disables_the_jj_version_backend() -> None:
    config = tomllib.loads((ROOT / "mise.toml").read_text())

    assert config.get("env", {}).get("SETUPTOOLS_SCM_DISABLE_JJ") == "1"
