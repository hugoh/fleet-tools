"""Fail when the build toolchain stops honouring per-package tag filtering.

Each package derives its version from `<pkg>-v*` tags in a shared repo. A
build-system upgrade (e.g. setuptools-scm 10 with hatch-vcs 0.4) can silently
pick another package's newer tag instead.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = ["asyncgh", "reconcilekit", "repokit"]


def run(*cmd: str, cwd: Path) -> str:
    return subprocess.run(
        cmd, cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


@pytest.mark.parametrize("pkg", PACKAGES)
def test_version_comes_from_own_tag(pkg: str, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / pkg / "src" / pkg).mkdir(parents=True)
    shutil.copy(ROOT / pkg / "pyproject.toml", repo / pkg / "pyproject.toml")
    (repo / pkg / "src" / pkg / "__init__.py").touch()
    (repo / pkg / "README.md").touch()

    run("git", "init", "-q", cwd=repo)
    run("git", "add", ".", cwd=repo)
    commit = (
        "git",
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "x",
    )
    run(*commit, cwd=repo)
    run("git", "tag", f"{pkg}-v1.2.3", cwd=repo)
    run(*commit, cwd=repo)
    run("git", "tag", "other-v9.9.9", cwd=repo)

    out = tmp_path / "dist"
    run("uv", "build", "--wheel", "--out-dir", str(out), pkg, cwd=repo)

    assert [w.name.split("-")[1] for w in out.glob("*.whl")] == ["1.2.4.dev1"]
