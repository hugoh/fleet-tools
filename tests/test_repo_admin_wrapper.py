"""The repo-admin wrapper must keep vcs-versioning off its jj backend.

In a colocated jj checkout that backend ignores the per-package tag filter and
picks a sibling package's tag, so building asyncgh/repokit/reconcilekit fails.
"""

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_wrapper_disables_the_jj_version_backend(tmp_path: Path) -> None:
    fake_uv = tmp_path / "uv"
    fake_uv.write_text('#!/usr/bin/env bash\necho "$SETUPTOOLS_SCM_DISABLE_JJ"\n')
    fake_uv.chmod(fake_uv.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}"}
    env.pop("SETUPTOOLS_SCM_DISABLE_JJ", None)

    out = subprocess.run(
        [str(ROOT / "repo-admin.sh")],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    assert out.strip() == "1"
