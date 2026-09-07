import asyncio
import base64
import subprocess

import httpx
import lib
import pytest
import respx
from lib import API_BASE, GhError, unmatched_include_forks

REPOS_JSON = [
    {
        "name": "public-repo",
        "fork": False,
        "archived": False,
        "private": False,
        "default_branch": "main",
    },
    {
        "name": "maintained-fork",
        "fork": True,
        "archived": False,
        "private": True,
        "default_branch": "master",
    },
]


def test_unmatched_include_forks_returns_names_with_no_matching_repo():
    assert unmatched_include_forks({"maintained-fork", "typo-fork"}, REPOS_JSON) == {
        "typo-fork"
    }


def test_unmatched_include_forks_empty_when_all_match():
    assert (
        unmatched_include_forks({"maintained-fork", "public-repo"}, REPOS_JSON) == set()
    )


def test_unmatched_include_forks_empty_for_no_include_forks():
    assert unmatched_include_forks(set(), REPOS_JSON) == set()


async def test_list_repos_raises_gh_error_for_unmatched_explicit_repo(
    monkeypatch, httpx2_mock: respx.Router
):
    monkeypatch.setattr("asyncgh.client._auth_token", lambda: "fake-token")
    httpx2_mock.get(f"{API_BASE}/user").mock(
        return_value=httpx.Response(200, json={"login": "someone-else"})
    )
    httpx2_mock.get(f"{API_BASE}/users/hugoh/repos").mock(
        return_value=httpx.Response(200, json=REPOS_JSON)
    )
    with pytest.raises(GhError, match="typo-repo"):
        await lib.list_repos(
            "hugoh", only={"public-repo", "typo-repo"}, require_only_match=True
        )


async def test_list_repos_does_not_raise_when_require_only_match_is_false(
    monkeypatch, httpx2_mock: respx.Router
):
    monkeypatch.setattr("asyncgh.client._auth_token", lambda: "fake-token")
    httpx2_mock.get(f"{API_BASE}/user").mock(
        return_value=httpx.Response(200, json={"login": "someone-else"})
    )
    httpx2_mock.get(f"{API_BASE}/users/hugoh/repos").mock(
        return_value=httpx.Response(200, json=REPOS_JSON)
    )
    repos = await lib.list_repos("hugoh", only={"public-repo", "typo-repo"})
    assert [r.name for r in repos] == ["public-repo"]


async def test_list_repos_does_not_raise_when_explicit_repo_is_only_excluded_by_skip(
    monkeypatch, httpx2_mock: respx.Router
):
    # A real repo named explicitly but also excluded via `skip` (e.g.
    # branch-protection-exclude.txt) isn't a typo -- require_only_match
    # checks against every fetched repo name, before skip is applied.
    monkeypatch.setattr("asyncgh.client._auth_token", lambda: "fake-token")
    httpx2_mock.get(f"{API_BASE}/user").mock(
        return_value=httpx.Response(200, json={"login": "someone-else"})
    )
    httpx2_mock.get(f"{API_BASE}/users/hugoh/repos").mock(
        return_value=httpx.Response(200, json=REPOS_JSON)
    )
    repos = await lib.list_repos(
        "hugoh",
        only={"public-repo"},
        skip={"public-repo"},
        require_only_match=True,
    )
    assert repos == []


async def test_default_owner_uses_gh_owner_env_without_a_network_call(monkeypatch):
    monkeypatch.setenv("GH_OWNER", "env-owner")
    assert await lib.default_owner() == "env-owner"


async def test_default_owner_falls_back_to_authenticated_user(
    monkeypatch, httpx2_mock: respx.Router
):
    monkeypatch.delenv("GH_OWNER", raising=False)
    monkeypatch.setattr("asyncgh.client._auth_token", lambda: "fake-token")
    httpx2_mock.get(f"{API_BASE}/user").mock(
        return_value=httpx.Response(200, json={"login": "authenticated-user"})
    )
    assert await lib.default_owner() == "authenticated-user"


async def test_default_owner_caches_the_resolved_value(
    monkeypatch, httpx2_mock: respx.Router
):
    monkeypatch.delenv("GH_OWNER", raising=False)
    monkeypatch.setattr("asyncgh.client._auth_token", lambda: "fake-token")
    route = httpx2_mock.get(f"{API_BASE}/user").mock(
        return_value=httpx.Response(200, json={"login": "authenticated-user"})
    )
    await lib.default_owner()
    await lib.default_owner()
    assert route.call_count == 1


async def test_default_owner_concurrent_callers_share_one_request(
    monkeypatch, httpx2_mock: respx.Router
):
    monkeypatch.delenv("GH_OWNER", raising=False)
    monkeypatch.setattr("asyncgh.client._auth_token", lambda: "fake-token")
    route = httpx2_mock.get(f"{API_BASE}/user").mock(
        return_value=httpx.Response(200, json={"login": "authenticated-user"})
    )
    results = await asyncio.gather(*(lib.default_owner() for _ in range(5)))
    assert results == ["authenticated-user"] * 5
    assert route.call_count == 1


def test_default_pages_domains_reads_mapping_from_file(tmp_path, monkeypatch):
    domains_file = tmp_path / "pages-domains.yaml"
    domains_file.write_text("awesome-jj: awesome-jj.larve.net\nhrd: hrd.larve.net\n")
    monkeypatch.setattr(lib, "PAGES_DOMAINS_FILE", domains_file)
    assert lib.default_pages_domains() == {
        "awesome-jj": "awesome-jj.larve.net",
        "hrd": "hrd.larve.net",
    }


def test_default_pages_domains_ignores_comments(tmp_path, monkeypatch):
    domains_file = tmp_path / "pages-domains.yaml"
    domains_file.write_text("# a comment\nawesome-jj: awesome-jj.larve.net\n")
    monkeypatch.setattr(lib, "PAGES_DOMAINS_FILE", domains_file)
    assert lib.default_pages_domains() == {"awesome-jj": "awesome-jj.larve.net"}


def test_default_branch_protection_exclude_reads_names_from_file(tmp_path, monkeypatch):
    exclude_file = tmp_path / "branch-protection-exclude.yaml"
    exclude_file.write_text("- homebrew-tap\n")
    monkeypatch.setattr(lib, "BRANCH_PROTECTION_EXCLUDE_FILE", exclude_file)
    monkeypatch.delenv("GH_BRANCH_PROTECTION_EXCLUDE", raising=False)
    assert lib.default_branch_protection_exclude() == {"homebrew-tap"}


def test_default_branch_protection_exclude_ignores_comments(tmp_path, monkeypatch):
    exclude_file = tmp_path / "branch-protection-exclude.yaml"
    exclude_file.write_text("# a comment\n- homebrew-tap\n")
    monkeypatch.setattr(lib, "BRANCH_PROTECTION_EXCLUDE_FILE", exclude_file)
    monkeypatch.delenv("GH_BRANCH_PROTECTION_EXCLUDE", raising=False)
    assert lib.default_branch_protection_exclude() == {"homebrew-tap"}


def test_default_branch_protection_exclude_empty_file_yields_empty_set(
    tmp_path, monkeypatch
):
    exclude_file = tmp_path / "branch-protection-exclude.yaml"
    exclude_file.write_text("# nothing yet\n")
    monkeypatch.setattr(lib, "BRANCH_PROTECTION_EXCLUDE_FILE", exclude_file)
    monkeypatch.delenv("GH_BRANCH_PROTECTION_EXCLUDE", raising=False)
    assert lib.default_branch_protection_exclude() == set()


def test_default_branch_protection_exclude_env_override(tmp_path, monkeypatch):
    exclude_file = tmp_path / "branch-protection-exclude.yaml"
    exclude_file.write_text("- homebrew-tap\n")
    monkeypatch.setattr(lib, "BRANCH_PROTECTION_EXCLUDE_FILE", exclude_file)
    monkeypatch.setenv("GH_BRANCH_PROTECTION_EXCLUDE", "other-repo,another-repo")
    assert lib.default_branch_protection_exclude() == {"other-repo", "another-repo"}


def test_default_include_forks_reads_yaml_list(tmp_path, monkeypatch):
    forks_file = tmp_path / "forks-include.yaml"
    forks_file.write_text("# maintained forks\n- Withings2Garmin\n")
    monkeypatch.setattr(lib, "FORKS_INCLUDE_FILE", forks_file)
    monkeypatch.delenv("GH_INCLUDE_FORKS", raising=False)
    assert lib.default_include_forks() == {"Withings2Garmin"}


@pytest.fixture
def enc_file(tmp_path, monkeypatch):
    path = tmp_path / "secrets.enc.yaml"
    monkeypatch.setattr(lib, "SECRETS_ENC_FILE", path)
    return path


_BINDINGS_YAML = (
    "TAP_GITHUB_TOKEN:\n"
    "  - repos: [hrd, jj-trim]\n"
    "    value: tok-a\n"
    "GIST_TOKEN:\n"
    "  - repos: [config]\n"
    "    value: tok-b\n"
    "  - repos: [gh-digest]\n"
    "    value: tok-c\n"
)


def test_load_secrets_parses_bindings_per_name(enc_file, monkeypatch):
    enc_file.write_text("placeholder")

    def fake_run(cmd, **kwargs):
        assert cmd == ["sops", "-d", str(enc_file)]
        return subprocess.CompletedProcess(cmd, 0, stdout=_BINDINGS_YAML, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert lib.load_secrets() == {
        "TAP_GITHUB_TOKEN": [{"repos": ["hrd", "jj-trim"], "value": "tok-a"}],
        "GIST_TOKEN": [
            {"repos": ["config"], "value": "tok-b"},
            {"repos": ["gh-digest"], "value": "tok-c"},
        ],
    }


def test_load_secrets_strips_sops_metadata_key(enc_file, monkeypatch):
    enc_file.write_text("placeholder")

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="N:\n  - repos: [r]\n    value: v\nsops:\n    age: []\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert lib.load_secrets() == {"N": [{"repos": ["r"], "value": "v"}]}


def test_load_secrets_rejects_non_list_spec(enc_file, monkeypatch):
    enc_file.write_text("placeholder")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(
            cmd, 0, stdout="N: v\n", stderr=""
        ),
    )
    with pytest.raises(GhError, match="expected a list"):
        lib.load_secrets()


def test_load_secrets_rejects_repo_in_two_bindings(enc_file, monkeypatch):
    enc_file.write_text("placeholder")
    dup = "N:\n  - repos: [r]\n    value: a\n  - repos: [r]\n    value: b\n"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout=dup, stderr=""),
    )
    with pytest.raises(GhError, match="more than one binding"):
        lib.load_secrets()


def test_load_secrets_raises_gh_error_on_nonzero_exit(enc_file, monkeypatch):
    enc_file.write_text("placeholder")

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="no key found")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(GhError, match="no key found"):
        lib.load_secrets()


def test_load_secrets_raises_gh_error_when_sops_not_on_path(enc_file, monkeypatch):
    enc_file.write_text("placeholder")

    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("sops")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(GhError, match="sops not found"):
        lib.load_secrets()


def test_load_secrets_raises_gh_error_when_file_missing(enc_file, monkeypatch):
    def fail_run(cmd, **kwargs):
        raise AssertionError("should not shell out to sops when the file is missing")

    monkeypatch.setattr(subprocess, "run", fail_run)
    with pytest.raises(GhError, match="not found"):
        lib.load_secrets()


def test_init_secrets_file_encrypts_template_via_sops_stdin(
    enc_file, tmp_path, monkeypatch
):
    config_file = tmp_path / ".sops.yaml"
    monkeypatch.setattr(lib, "SOPS_CONFIG_FILE", config_file)

    def fake_run(cmd, **kwargs):
        assert cmd == [
            "sops",
            "--encrypt",
            "--config",
            str(config_file),
            "--filename-override",
            str(enc_file),
            "--input-type",
            "yaml",
            "--output-type",
            "yaml",
            "/dev/stdin",
        ]
        assert kwargs["input"] == "NAME: ''\n"
        return subprocess.CompletedProcess(cmd, 0, stdout="NAME: ENC[...]\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    lib.init_secrets_file("NAME: ''\n")
    assert enc_file.read_text() == "NAME: ENC[...]\n"


def test_init_secrets_file_raises_gh_error_on_nonzero_exit(enc_file, monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="no key found")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(GhError, match="no key found"):
        lib.init_secrets_file("NAME: ''\n")
    assert not enc_file.exists()


def test_init_secrets_file_raises_gh_error_when_sops_not_on_path(enc_file, monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("sops")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(GhError, match="sops not found"):
        lib.init_secrets_file("NAME: ''\n")


def test_edit_secrets_file_runs_sops_on_the_file_and_returns_exit_code(
    enc_file, monkeypatch
):
    def fake_run(cmd, **kwargs):
        assert cmd == ["sops", str(enc_file)]
        assert "capture_output" not in kwargs  # inherits stdio for the editor session
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert lib.edit_secrets_file() == 0


def test_edit_secrets_file_returns_nonzero_exit_code(enc_file, monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert lib.edit_secrets_file() == 1


def test_edit_secrets_file_raises_gh_error_when_sops_not_on_path(enc_file, monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("sops")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(GhError, match="sops not found"):
        lib.edit_secrets_file()


def test_default_variables_reads_repo_list(tmp_path, monkeypatch):
    variables_file = tmp_path / "variables.yaml"
    variables_file.write_text("SMTP_HOST:\n  repos: [gh-digest]\n")
    monkeypatch.setattr(lib, "VARIABLES_FILE", variables_file)
    assert lib.default_variables() == {"SMTP_HOST": ["gh-digest"]}


def test_decrypt_variables_reads_from_the_variables_enc_file(tmp_path, monkeypatch):
    enc = tmp_path / "variables.enc.yaml"
    enc.write_text("placeholder")
    monkeypatch.setattr(lib, "VARIABLES_ENC_FILE", enc)

    def fake_run(cmd, **kwargs):
        assert cmd == ["sops", "-d", str(enc)]
        return subprocess.CompletedProcess(
            cmd, 0, stdout="SMTP_PORT: '587'\n", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert lib.decrypt_variables() == {"SMTP_PORT": "587"}


def test_edit_variables_file_runs_sops_on_the_variables_enc_file(tmp_path, monkeypatch):
    enc = tmp_path / "variables.enc.yaml"
    monkeypatch.setattr(lib, "VARIABLES_ENC_FILE", enc)

    def fake_run(cmd, **kwargs):
        assert cmd == ["sops", str(enc)]
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert lib.edit_variables_file() == 0


def test_write_enc_file_encrypts_a_mapping_via_sops_stdin(tmp_path, monkeypatch):
    enc = tmp_path / "variables.enc.yaml"
    config_file = tmp_path / ".sops.yaml"
    monkeypatch.setattr(lib, "SOPS_CONFIG_FILE", config_file)

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["sops", "--encrypt"]
        assert "--filename-override" in cmd
        assert kwargs["input"] == "A: '1'\nB: two\n"
        return subprocess.CompletedProcess(cmd, 0, stdout="ENC\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    lib.write_enc_file(enc, {"A": "1", "B": "two"})
    assert enc.read_text() == "ENC\n"


def test_workflow_config_names_splits_secrets_and_vars_and_drops_github_token():
    text = (
        "run: echo ${{ secrets.PR_DIGEST_PAT }} ${{ secrets.GITHUB_TOKEN }}\n"
        "with:\n  host: ${{ vars.SMTP_HOST }}\n  host2: ${{  vars.SMTP_HOST  }}\n"
    )
    secrets, variables = lib.workflow_config_names([text])
    assert secrets == {"PR_DIGEST_PAT"}
    assert variables == {"SMTP_HOST"}


async def test_fetch_workflow_texts_downloads_each_yaml_file(
    httpx2_mock: respx.Router, monkeypatch
):
    monkeypatch.setattr("asyncgh.client._auth_token", lambda: "fake-token")
    monkeypatch.setenv("GH_OWNER", "hugoh")
    httpx2_mock.get(
        f"{API_BASE}/repos/hugoh/gh-digest/contents/.github/workflows"
    ).mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "type": "file",
                    "name": "digest.yml",
                    "path": ".github/workflows/digest.yml",
                },
                {
                    "type": "file",
                    "name": "notes.md",
                    "path": ".github/workflows/notes.md",
                },
            ],
        )
    )
    httpx2_mock.get(
        f"{API_BASE}/repos/hugoh/gh-digest/contents/.github/workflows/digest.yml"
    ).mock(
        return_value=httpx.Response(
            200,
            json={"content": base64.b64encode(b"on: push\n").decode()},
        )
    )
    assert await lib.fetch_workflow_texts("hugoh", "gh-digest") == ["on: push\n"]


async def test_fetch_workflow_texts_returns_empty_when_no_workflows_dir(
    httpx2_mock: respx.Router, monkeypatch
):
    monkeypatch.setattr("asyncgh.client._auth_token", lambda: "fake-token")
    httpx2_mock.get(f"{API_BASE}/repos/hugoh/repo/contents/.github/workflows").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )
    assert await lib.fetch_workflow_texts("hugoh", "repo") == []
