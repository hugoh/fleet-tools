import argparse
import subprocess
from pathlib import Path

import pytest
import scaffold


def _args(path: Path, **overrides: object) -> argparse.Namespace:
    base = {
        "path": str(path),
        "name": None,
        "release": False,
        "pypi": False,
        "pypi_publish_ref": "abc1234 # v1.99.0",
        "pages": False,
        "action": False,
        "rerun_transient": False,
        "tests": "none",
        "shell": False,
        "apt_packages": None,
        "pre_hk": None,
        "default_branch": "main",
        "gh_workflows_ref": "deadbeef1234 # v1.99.0",
        "rerun_transient_ref": "cafef00d # v0.9.9",
        "pages_dir": "site",
        "pages_build_cmd": "mise run pages-build",
        "watch_workflows": "[hk]",
        "force": None,
        "no_pin": True,
        "dry_run": False,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


async def _run(path: Path, **overrides: object) -> int:
    return await scaffold.run(_args(path, **overrides))


async def test_minimal_scaffold_writes_baseline(tmp_path: Path) -> None:
    target = tmp_path / "widget"
    assert await _run(target) == 0

    for name in (
        ".editorconfig",
        ".gitignore",
        ".ryl.toml",
        "biome.json",
        "hk.pkl",
        "mise.toml",
        ".renovaterc.json",
        ".github/workflows/hk.yml",
    ):
        assert (target / name).is_file(), name
    assert not (target / ".yamllint").exists()
    assert not (target / ".github/workflows/release.yml").exists()
    assert not (target / "action.yml").exists()


async def test_workflows_carry_no_yamllint_directives(tmp_path: Path) -> None:
    target = tmp_path / "widget"
    await _run(target, release=True, pages=True)
    for wf in (target / ".github/workflows").glob("*.yml"):
        assert "yamllint" not in wf.read_text(), wf


async def test_ryl_config_matches_the_fleet_copy(tmp_path: Path) -> None:
    target = tmp_path / "widget"
    await _run(target)
    fleet = (scaffold.REPO_ROOT / ".ryl.toml").read_text()
    assert (target / ".ryl.toml").read_text() == fleet


async def test_biome_schema_tracks_canonical_biome_version(tmp_path: Path) -> None:
    version = scaffold._canonical_tools()["biome"]
    target = tmp_path / "widget"
    await _run(target)
    assert f"/schemas/{version}/schema.json" in (target / "biome.json").read_text()


async def test_no_template_markers_leak(tmp_path: Path) -> None:
    target = tmp_path / "widget"
    await _run(
        target,
        release=True,
        pypi=True,
        pages=True,
        action=True,
        rerun_transient=True,
        tests="python",
        shell=True,
    )
    for f in target.rglob("*"):
        if not f.is_file() or {".git", ".jj"} & set(f.parts):
            continue
        text = f.read_text(encoding="utf-8", errors="ignore")
        assert "<<" not in text and "<%" not in text, f


async def test_tool_versions_come_from_gh_workflows_mise_toml(tmp_path: Path) -> None:
    canonical = scaffold._canonical_tools()
    target = tmp_path / "widget"
    await _run(target, shell=True, tests="python")
    mise = (target / "mise.toml").read_text()
    assert f'hk = "{canonical["hk"]}"' in mise
    assert f'shellcheck = "{canonical["shellcheck"]}"' in mise
    assert f'ruff = "{canonical["ruff"]}"' in mise
    # gh-workflows-only tools are not propagated
    assert "sops" not in mise


async def test_hk_groups_track_flags(tmp_path: Path) -> None:
    plain = tmp_path / "a"
    await _run(plain)
    assert "...Base.shell" not in (plain / "hk.pkl").read_text()
    assert "...Base.python" not in (plain / "hk.pkl").read_text()

    full = tmp_path / "b"
    await _run(full, shell=True, tests="python")
    hk = (full / "hk.pkl").read_text()
    assert "...Base.shell" in hk
    assert "...Base.python" in hk
    assert "unittest discover" in hk


async def test_action_flag_adds_renovate_rule_and_major_tag(tmp_path: Path) -> None:
    target = tmp_path / "act"
    await _run(target, action=True, release=True)
    assert (
        "github>hugoh/renovate-config//presets/action-file"
        in (target / ".renovaterc.json").read_text()
    )
    assert "major-tag: true" in (target / ".github/workflows/release.yml").read_text()
    assert (target / "action.yml").is_file()


async def test_pypi_implies_release_and_adds_a_trusted_publish_job(
    tmp_path: Path,
) -> None:
    target = tmp_path / "widget"
    await _run(target, pypi=True)
    release = (target / ".github/workflows/release.yml").read_text()
    assert "  publish-pypi:" in release
    assert "needs: release" in release
    assert "needs.release.outputs.tag != ''" in release
    assert "environment: pypi" in release
    assert "ref: ${{ needs.release.outputs.tag }}" in release
    assert "fetch-depth: 0" in release
    assert "run: uv build" in release
    assert "pypa/gh-action-pypi-publish@abc1234 # v1.99.0" in release
    assert "skip-existing: true" in release


async def test_publish_job_has_only_the_oidc_permission(tmp_path: Path) -> None:
    yaml = pytest.importorskip("yaml")
    target = tmp_path / "widget"
    await _run(target, pypi=True)
    workflow = yaml.safe_load((target / ".github/workflows/release.yml").read_text())
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["release"]["permissions"] == {"contents": "write"}
    assert workflow["jobs"]["publish-pypi"]["permissions"] == {"id-token": "write"}


async def test_release_without_pypi_publishes_nothing(tmp_path: Path) -> None:
    target = tmp_path / "widget"
    await _run(target, release=True)
    release = (target / ".github/workflows/release.yml").read_text()
    assert "publish-pypi" not in release
    assert "pypi" not in (target / "mise.toml").read_text()
    assert "package-check" not in (target / "hk.pkl").read_text()


async def test_pypi_adds_a_packaging_check(tmp_path: Path) -> None:
    canonical = scaffold._canonical_tools()
    target = tmp_path / "widget"
    await _run(target, pypi=True)
    mise = (target / "mise.toml").read_text()
    assert f'"pipx:twine" = "{canonical["pipx:twine"]}"' in mise
    assert "[tasks.package-check]" in mise
    assert "uv build --out-dir dist" in mise
    assert "twine check --strict dist/*" in mise
    assert "m.version('widget')" in mise
    hk = (target / "hk.pkl").read_text()
    assert '"package-check"' in hk or "mise run package-check" in hk
    assert 'List("ci")' in hk


async def test_the_packaging_check_is_independent_of_the_test_flavour(
    tmp_path: Path,
) -> None:
    target = tmp_path / "widget"
    await _run(target, pypi=True, tests="python")
    assert "[tasks.package-check]" in (target / "mise.toml").read_text()
    assert "[tasks.test]" in (target / "mise.toml").read_text()


async def test_idempotent_keeps_existing_files(tmp_path: Path) -> None:
    target = tmp_path / "widget"
    await _run(target)
    (target / "hk.pkl").write_text("# hand-edited\n")
    await _run(target)
    assert (target / "hk.pkl").read_text() == "# hand-edited\n"

    await _run(target, force=[])
    assert (target / "hk.pkl").read_text() != "# hand-edited\n"


async def test_targeted_force_overwrites_only_named_paths(tmp_path: Path) -> None:
    target = tmp_path / "widget"
    await _run(target, release=True)
    (target / "hk.pkl").write_text("# keep me\n")
    (target / ".github/workflows/hk.yml").write_text("# stale caller\n")

    await _run(target, release=True, force=[".github/workflows/hk.yml"])
    assert (target / "hk.pkl").read_text() == "# keep me\n"
    assert "stale caller" not in (target / ".github/workflows/hk.yml").read_text()
    assert (
        "uses: hugoh/gh-workflows" in (target / ".github/workflows/hk.yml").read_text()
    )


async def test_existing_git_repo_is_not_reinitialised(tmp_path: Path) -> None:
    target = tmp_path / "widget"
    target.mkdir()
    (target / ".git").mkdir()
    await _run(target)
    assert not (target / ".jj").exists()


async def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    target = tmp_path / "widget"
    await _run(target, dry_run=True)
    assert not target.exists() or not any(target.iterdir())


async def test_default_branch_flows_into_workflows(tmp_path: Path) -> None:
    target = tmp_path / "widget"
    await _run(target, default_branch="trunk", release=True)
    assert "- trunk" in (target / ".github/workflows/hk.yml").read_text()
    assert "- trunk" in (target / ".github/workflows/release.yml").read_text()


async def test_rendered_workflows_are_valid_yaml(tmp_path: Path) -> None:
    yaml = pytest.importorskip("yaml")
    target = tmp_path / "widget"
    await _run(target, pypi=True, pages=True, rerun_transient=True)
    for wf in (target / ".github/workflows").glob("*.yml"):
        yaml.safe_load(wf.read_text())


def test_scaffolded_repo_passes_jactionlint(tmp_path: Path) -> None:
    if not _have("jactionlint"):
        pytest.skip("jactionlint not on PATH")
    import asyncio

    target = tmp_path / "widget"
    asyncio.run(
        _run(
            target,
            release=True,
            pypi=True,
            pages=True,
            rerun_transient=True,
            action=True,
        )
    )
    proc = subprocess.run(
        [
            "jactionlint",
            "--ignore=unpinned-uses",
            *map(str, (target / ".github/workflows").glob("*.yml")),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def _have(tool: str) -> bool:
    from shutil import which

    return which(tool) is not None


class _FakeGh:
    def __init__(self, tag: str = "v1.2.3", sha: str = "c0ffee") -> None:
        self.tag = tag
        self.sha = sha
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        out = self.tag if cmd[1] == "release" else self.sha
        return subprocess.CompletedProcess(cmd, 0, stdout=out + "\n")


def test_resolve_ref_pins_the_commit_not_the_tag_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeGh(tag="v1.14.3", sha="7245906")
    monkeypatch.setattr(scaffold.subprocess, "run", fake)
    assert scaffold._resolve_ref("pypa/x", None) == "7245906 # v1.14.3"
    api = fake.calls[1]
    assert "repos/pypa/x/commits/v1.14.3" in api
    assert not any("git/ref/tags" in part for part in api)


def test_resolve_ref_returns_explicit_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeGh()
    monkeypatch.setattr(scaffold.subprocess, "run", fake)
    assert scaffold._resolve_ref("a/b", "abc # v1") == "abc # v1"
    assert fake.calls == []


def test_resolve_ref_falls_back_to_main_when_gh_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(cmd: list[str], **_: object) -> None:
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(scaffold.subprocess, "run", boom)
    assert scaffold._resolve_ref("a/b", None) == "main"
