import argparse

import httpx
import protection
import pytest
import repo_admin
from helpers import PRIVATE_REPO, REPO, _FakeResponse, _FakeResponseWithJson
from lib import GhError, Repo, Status


class _MissingPath:
    name = "secrets.enc.yaml"

    def exists(self):
        return False


class _PresentPath:
    def exists(self):
        return True


def _async_return(value):
    async def _fake(*args, **kwargs):
        return value

    return _fake


def _capturing_list_repos():
    seen = {}

    async def fake_list_repos(owner, *, only=None, skip=None, require_only_match=False):
        seen["only"] = only
        seen["skip"] = skip
        seen["require_only_match"] = require_only_match
        return []

    return seen, fake_list_repos


def _capturing_list_repos_calls():
    calls = []

    async def fake_list_repos(owner, *, only=None, skip=None, require_only_match=False):
        calls.append(
            {"only": only, "skip": skip, "require_only_match": require_only_match}
        )
        return []

    return calls, fake_list_repos


# ---------------------------------------------------------------------------
# repos list
# ---------------------------------------------------------------------------


async def test_cmd_repos_list_prints_a_row_per_repo(monkeypatch, capsys):
    async def fake_list_repos(owner, *, only=None, skip=None, require_only_match=False):
        return [
            Repo(name="repo-a", default_branch="main", is_private=False, is_fork=False),
            Repo(name="repo-b", default_branch="master", is_private=True, is_fork=True),
        ]

    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    args = argparse.Namespace(repos=[], skip=None)
    assert await repo_admin.cmd_repos_list(args) == 0
    out = capsys.readouterr().out
    assert "repo-a" in out
    assert "repo-b" in out
    assert "NAME" in out
    assert "DEFAULT BRANCH" in out


async def test_cmd_repos_list_passes_through_repos_and_skip_filters(monkeypatch):
    seen, fake_list_repos = _capturing_list_repos()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    args = argparse.Namespace(repos=["repo-a"], skip="repo-b")
    await repo_admin.cmd_repos_list(args)
    assert seen == {
        "only": {"repo-a"},
        "skip": {"repo-b"},
        "require_only_match": True,
    }


async def test_cmd_repos_list_does_not_require_a_match_with_no_repo_args(monkeypatch):
    seen, fake_list_repos = _capturing_list_repos()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    args = argparse.Namespace(repos=[], skip=None)
    await repo_admin.cmd_repos_list(args)
    assert seen["require_only_match"] is False


# ---------------------------------------------------------------------------
# merge sync
# ---------------------------------------------------------------------------


def test_merge_settings_dry_run_line_up_to_date():
    current = {
        "allow_auto_merge": True,
        "delete_branch_on_merge": True,
        "allow_update_branch": True,
    }
    assert repo_admin.merge_settings_dry_run_line(
        "repo", current, Status.UNCHANGED
    ) == (f"{'repo':<30} unchanged: {current}")


def test_merge_settings_dry_run_line_lists_disabled_in_field_order():
    current = {
        "allow_auto_merge": False,
        "delete_branch_on_merge": True,
        "allow_update_branch": False,
    }
    line = repo_admin.merge_settings_dry_run_line("repo", current, Status.OK)
    assert line == f"{'repo':<30} would enable: allow_auto_merge, allow_update_branch"


def test_merge_settings_apply_line_unchanged():
    settings = {
        "allow_auto_merge": True,
        "delete_branch_on_merge": True,
        "allow_update_branch": True,
    }
    assert repo_admin.merge_settings_apply_line(
        "repo", settings, settings, Status.UNCHANGED
    ) == (f"{'repo':<30} unchanged: {settings}")


def test_merge_settings_apply_line_changed():
    before = {
        "allow_auto_merge": False,
        "delete_branch_on_merge": True,
        "allow_update_branch": True,
    }
    after = {
        "allow_auto_merge": True,
        "delete_branch_on_merge": True,
        "allow_update_branch": True,
    }
    line = repo_admin.merge_settings_apply_line("repo", before, after, Status.OK)
    assert line == f"{'repo':<30} {before} -> {after}"


def _merge_settings_dry_run_worker(monkeypatch, settings):
    async def fake_merge_settings(owner, name):
        return settings

    monkeypatch.setattr(repo_admin, "_merge_settings", fake_merge_settings)
    return repo_admin.make_merge_settings_worker(owner="hugoh", dry_run=True)


async def test_merge_settings_worker_dry_run(monkeypatch):
    worker = _merge_settings_dry_run_worker(
        monkeypatch,
        {
            "allow_auto_merge": False,
            "delete_branch_on_merge": True,
            "allow_update_branch": True,
        },
    )
    result = await worker(REPO)
    assert "would enable: allow_auto_merge" in result.line


def test_merge_settings_at_target_true_when_all_enabled():
    assert repo_admin.merge_settings_at_target(
        {
            "allow_auto_merge": True,
            "delete_branch_on_merge": True,
            "allow_update_branch": True,
        }
    )


def test_merge_settings_at_target_false_when_any_disabled():
    assert not repo_admin.merge_settings_at_target(
        {
            "allow_auto_merge": True,
            "delete_branch_on_merge": False,
            "allow_update_branch": True,
        }
    )


async def test_merge_settings_worker_dry_run_unchanged_when_at_target(monkeypatch):
    worker = _merge_settings_dry_run_worker(
        monkeypatch,
        {
            "allow_auto_merge": True,
            "delete_branch_on_merge": True,
            "allow_update_branch": True,
        },
    )
    assert (await worker(REPO)).status == Status.UNCHANGED


async def test_merge_settings_worker_dry_run_ok_when_would_reach_target(monkeypatch):
    worker = _merge_settings_dry_run_worker(
        monkeypatch,
        {
            "allow_auto_merge": False,
            "delete_branch_on_merge": True,
            "allow_update_branch": True,
        },
    )
    assert (await worker(REPO)).status == Status.OK


def test_merge_settings_dry_run_line_marks_gated_field_unavailable():
    current = {
        "allow_auto_merge": False,
        "delete_branch_on_merge": True,
        "allow_update_branch": True,
    }
    line = repo_admin.merge_settings_dry_run_line(
        "repo", current, Status.LIMITED_UNCHANGED, is_private=True
    )
    assert "would enable" not in line
    assert "(unavailable: allow_auto_merge)" in line


def test_merge_settings_dry_run_line_would_enable_and_unavailable_together():
    current = {
        "allow_auto_merge": False,
        "delete_branch_on_merge": False,
        "allow_update_branch": True,
    }
    line = repo_admin.merge_settings_dry_run_line(
        "repo", current, Status.LIMITED, is_private=True
    )
    assert "would enable: delete_branch_on_merge" in line
    assert "(unavailable: allow_auto_merge)" in line


async def test_merge_settings_worker_dry_run_limited_unchanged_on_private_repo_gate(
    monkeypatch,
):
    worker = _merge_settings_dry_run_worker(
        monkeypatch,
        {
            "allow_auto_merge": False,
            "delete_branch_on_merge": True,
            "allow_update_branch": True,
        },
    )
    result = await worker(PRIVATE_REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    assert "would enable" not in result.line
    assert "unavailable: allow_auto_merge" in result.line


async def test_merge_settings_worker_dry_run_limited_when_private_repo_has_fixable_field(
    monkeypatch,
):
    worker = _merge_settings_dry_run_worker(
        monkeypatch,
        {
            "allow_auto_merge": False,
            "delete_branch_on_merge": False,
            "allow_update_branch": True,
        },
    )
    result = await worker(PRIVATE_REPO)
    assert result.status == Status.LIMITED
    assert "would enable: delete_branch_on_merge" in result.line
    assert "unavailable: allow_auto_merge" in result.line


def _merge_settings_apply_worker(monkeypatch, before, after):
    calls = iter([before, after])

    async def fake_merge_settings(owner, name):
        return next(calls)

    async def fake_api_json(*a, **k):
        return {}

    monkeypatch.setattr(repo_admin, "_merge_settings", fake_merge_settings)
    monkeypatch.setattr(repo_admin, "api_json", fake_api_json)
    return repo_admin.make_merge_settings_worker(owner="hugoh", dry_run=False)


AT_TARGET = {
    "allow_auto_merge": True,
    "delete_branch_on_merge": True,
    "allow_update_branch": True,
}
NOT_AT_TARGET = {
    "allow_auto_merge": False,
    "delete_branch_on_merge": True,
    "allow_update_branch": True,
}
PARTIALLY_FIXED_NOT_AT_TARGET = {
    "allow_auto_merge": False,
    "delete_branch_on_merge": True,
    "allow_update_branch": False,
}


async def test_merge_settings_worker_apply_ok_when_reaches_target(monkeypatch):
    worker = _merge_settings_apply_worker(monkeypatch, NOT_AT_TARGET, AT_TARGET)
    assert (await worker(REPO)).status == Status.OK


async def test_merge_settings_worker_apply_unchanged_when_already_at_target(
    monkeypatch,
):
    worker = _merge_settings_apply_worker(monkeypatch, AT_TARGET, AT_TARGET)
    assert (await worker(REPO)).status == Status.UNCHANGED


async def test_merge_settings_worker_apply_limited_when_still_not_at_target(
    monkeypatch,
):
    worker = _merge_settings_apply_worker(monkeypatch, NOT_AT_TARGET, NOT_AT_TARGET)
    assert (await worker(REPO)).status == Status.LIMITED_UNCHANGED


async def test_merge_settings_worker_apply_limited_when_partially_fixed(monkeypatch):
    worker = _merge_settings_apply_worker(
        monkeypatch, NOT_AT_TARGET, PARTIALLY_FIXED_NOT_AT_TARGET
    )
    assert (await worker(REPO)).status == Status.LIMITED


# ---------------------------------------------------------------------------
# squash-merge commit title
# ---------------------------------------------------------------------------

SQUASH_ON = {
    "squash_merge_commit_title": "PR_TITLE",
    "squash_merge_commit_message": "COMMIT_MESSAGES",
    "allow_squash_merge": True,
    "allow_merge_commit": False,
    "allow_rebase_merge": False,
}
SQUASH_OFF = {
    "squash_merge_commit_title": "COMMIT_OR_PR_TITLE",
    "squash_merge_commit_message": "COMMIT_MESSAGES",
    "allow_squash_merge": True,
    "allow_merge_commit": True,
    "allow_rebase_merge": True,
}


def test_has_semantic_pr_check_bare_context():
    assert repo_admin._has_semantic_pr_check(["hk / lint", "semantic-pr"])


def test_has_semantic_pr_check_reusable_form():
    assert repo_admin._has_semantic_pr_check(["semantic-pr / semantic-pr"])


def test_has_semantic_pr_check_absent():
    assert not repo_admin._has_semantic_pr_check(["hk / lint", "goci"])
    assert not repo_admin._has_semantic_pr_check(["not-semantic-pr / x"])


def test_squash_title_at_target():
    assert repo_admin.squash_title_at_target(SQUASH_ON)
    assert not repo_admin.squash_title_at_target(SQUASH_OFF)
    assert not repo_admin.squash_title_at_target(
        {**SQUASH_ON, "allow_rebase_merge": True}
    )
    assert not repo_admin.squash_title_at_target({})


def test_squash_title_line_not_applicable():
    line = repo_admin.squash_title_line(
        "repo", SQUASH_OFF, None, Status.UNCHANGED, applies=False
    )
    assert line == f"{'repo':<30} unchanged: semantic-pr not a required check"


def test_squash_title_line_dry_run_would_set():
    line = repo_admin.squash_title_line(
        "repo", SQUASH_OFF, None, Status.OK, applies=True
    )
    assert "would set: squash_merge_commit_title=PR_TITLE" in line


def test_squash_title_line_apply_changed():
    line = repo_admin.squash_title_line(
        "repo", SQUASH_OFF, SQUASH_ON, Status.OK, applies=True
    )
    assert line == f"{'repo':<30} {SQUASH_OFF} -> {SQUASH_ON}"


def _squash_title_worker(monkeypatch, *, current, applies, after=None, dry_run=True):
    states = iter([current, after if after is not None else current])

    async def fake_squash_settings(owner, name):
        return next(states)

    async def fake_required(owner, name, default_branch):
        return applies

    async def fake_api_json(*a, **k):
        return {}

    monkeypatch.setattr(repo_admin, "_squash_settings", fake_squash_settings)
    monkeypatch.setattr(repo_admin, "_semantic_pr_required", fake_required)
    monkeypatch.setattr(repo_admin, "api_json", fake_api_json)
    return repo_admin.make_squash_title_worker(owner="hugoh", dry_run=dry_run)


async def test_squash_title_worker_quiet_when_not_required(monkeypatch):
    worker = _squash_title_worker(monkeypatch, current=SQUASH_OFF, applies=False)
    result = await worker(REPO)
    assert result.status == Status.UNCHANGED
    assert "not a required check" in result.line


async def test_squash_title_worker_quiet_when_already_at_target(monkeypatch):
    worker = _squash_title_worker(monkeypatch, current=SQUASH_ON, applies=True)
    assert (await worker(REPO)).status == Status.UNCHANGED


async def test_squash_title_worker_dry_run_would_change(monkeypatch):
    worker = _squash_title_worker(monkeypatch, current=SQUASH_OFF, applies=True)
    result = await worker(REPO)
    assert result.status == Status.OK
    assert "would set" in result.line


async def test_squash_title_worker_apply_reaches_target(monkeypatch):
    worker = _squash_title_worker(
        monkeypatch, current=SQUASH_OFF, applies=True, after=SQUASH_ON, dry_run=False
    )
    assert (await worker(REPO)).status == Status.OK


async def test_squash_title_worker_apply_does_not_reach_target(monkeypatch):
    worker = _squash_title_worker(
        monkeypatch, current=SQUASH_OFF, applies=True, after=SQUASH_OFF, dry_run=False
    )
    assert (await worker(REPO)).status == Status.LIMITED_UNCHANGED


class _Resp:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self.is_success = status_code < 400
        self._body = body or {}

    def json(self):
        return self._body


def _semantic_pr_required_env(monkeypatch, *, classic, repo_rulesets=()):
    async def fake_api_raw(method, path, *a, **k):
        return _Resp(*classic)

    async def fake_matching_rulesets(owner, name, default_branch):
        return list(repo_rulesets), []

    monkeypatch.setattr(repo_admin, "api_raw", fake_api_raw)
    monkeypatch.setattr(protection, "_matching_rulesets", fake_matching_rulesets)


async def test_semantic_pr_required_from_classic_protection(monkeypatch):
    _semantic_pr_required_env(
        monkeypatch,
        classic=(
            200,
            {"required_status_checks": {"contexts": ["hk / lint", "semantic-pr"]}},
        ),
    )
    assert await repo_admin._semantic_pr_required("hugoh", "repo", "main") is True


async def test_semantic_pr_required_false_when_absent(monkeypatch):
    _semantic_pr_required_env(
        monkeypatch,
        classic=(200, {"required_status_checks": {"contexts": ["hk / lint"]}}),
    )
    assert await repo_admin._semantic_pr_required("hugoh", "repo", "main") is False


async def test_semantic_pr_required_false_when_no_protection(monkeypatch):
    _semantic_pr_required_env(monkeypatch, classic=(404,))
    assert await repo_admin._semantic_pr_required("hugoh", "repo", "main") is False


# ---------------------------------------------------------------------------
# security sync
# ---------------------------------------------------------------------------


def test_security_summarize_all_available_and_enabled():
    repo_json = {
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
        }
    }
    summary = repo_admin.security_summarize(
        repo_json,
        vuln_alerts_enabled=True,
        pvr_json={"enabled": True},
        codeql_json={"state": "configured"},
    )
    assert summary == {"would_enable": [], "unavailable": []}


def test_security_summarize_reports_would_enable():
    repo_json = {
        "security_and_analysis": {
            "secret_scanning": {"status": "disabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
        }
    }
    summary = repo_admin.security_summarize(
        repo_json,
        vuln_alerts_enabled=False,
        pvr_json={"enabled": True},
        codeql_json={"state": "not-configured"},
    )
    assert set(summary["would_enable"]) == {
        "vuln_alerts",
        "secret_scanning",
        "code_scanning",
    }
    assert summary["unavailable"] == []


def test_security_summarize_reports_dependabot_security_updates_on():
    repo_json = {
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
            "dependabot_security_updates": {"status": "enabled"},
        }
    }
    summary = repo_admin.security_summarize(
        repo_json,
        vuln_alerts_enabled=True,
        pvr_json={"enabled": True},
        codeql_json={"state": "configured"},
    )
    assert summary["would_enable"] == ["dependabot_updates_off"]


def test_security_summarize_reports_unavailable_for_private_repo():
    # Private repos without GitHub Advanced Security: these keys are absent
    # from security_and_analysis, and private-vulnerability-reporting and
    # code-scanning default setup both 404.
    repo_json = {"security_and_analysis": {}}
    summary = repo_admin.security_summarize(
        repo_json,
        vuln_alerts_enabled=True,
        pvr_json=None,
        codeql_json=None,
    )
    assert set(summary["unavailable"]) == {
        "secret_scanning",
        "push_protection",
        "private_vuln_reporting",
        "code_scanning",
    }
    assert summary["would_enable"] == []


def test_security_dry_run_line_up_to_date():
    line = repo_admin.security_dry_run_line(
        "repo", {"would_enable": [], "unavailable": []}, Status.UNCHANGED
    )
    assert line == f"{'repo':<30} unchanged: enabled"


def test_security_dry_run_line_would_enable_and_unavailable():
    line = repo_admin.security_dry_run_line(
        "repo",
        {"would_enable": ["vuln_alerts"], "unavailable": ["push_protection"]},
        Status.LIMITED,
    )
    assert (
        line == f"{'repo':<30} would enable: vuln_alerts (unavailable: push_protection)"
    )


FULLY_ENABLED_REPO_JSON = {
    "security_and_analysis": {
        "secret_scanning": {"status": "enabled"},
        "secret_scanning_push_protection": {"status": "enabled"},
    }
}
UNAVAILABLE_REPO_JSON = {"security_and_analysis": {}}
CONFIGURED_CODEQL_JSON = {"state": "configured"}


def _security_worker(
    monkeypatch,
    *,
    repo_json,
    vuln_alerts_enabled,
    pvr_json,
    dry_run,
    codeql_json=None,
    api_responses=(),
    calls=None,
):
    async def fake_fetch_security_state(owner, name):
        return repo_json, vuln_alerts_enabled, pvr_json, codeql_json

    responses_iter = iter(api_responses)

    async def fake_api_json(*a, **k):
        return {}

    async def fake_api_raw(*a, **k):
        if calls is not None:
            calls.append((a, k))
        return next(responses_iter)

    monkeypatch.setattr(repo_admin, "_fetch_security_state", fake_fetch_security_state)
    monkeypatch.setattr(repo_admin, "api_json", fake_api_json)
    monkeypatch.setattr(repo_admin, "api_raw", fake_api_raw)
    return repo_admin.make_security_features_worker(owner="hugoh", dry_run=dry_run)


async def test_security_worker_dry_run_unchanged_when_fully_enabled(monkeypatch):
    worker = _security_worker(
        monkeypatch,
        repo_json=FULLY_ENABLED_REPO_JSON,
        vuln_alerts_enabled=True,
        pvr_json={"enabled": True},
        codeql_json=CONFIGURED_CODEQL_JSON,
        dry_run=True,
    )
    assert (await worker(REPO)).status == Status.UNCHANGED


async def test_security_worker_dry_run_ok_when_would_enable(monkeypatch):
    worker = _security_worker(
        monkeypatch,
        repo_json=FULLY_ENABLED_REPO_JSON,
        vuln_alerts_enabled=False,
        pvr_json={"enabled": True},
        codeql_json=CONFIGURED_CODEQL_JSON,
        dry_run=True,
    )
    assert (await worker(REPO)).status == Status.OK


async def test_security_worker_dry_run_limited_unchanged_when_unavailable_and_nothing_pending(
    monkeypatch,
):
    worker = _security_worker(
        monkeypatch,
        repo_json=UNAVAILABLE_REPO_JSON,
        vuln_alerts_enabled=True,
        pvr_json=None,
        dry_run=True,
    )
    assert (await worker(REPO)).status == Status.LIMITED_UNCHANGED


async def test_security_worker_dry_run_limited_when_unavailable_and_would_enable(
    monkeypatch,
):
    worker = _security_worker(
        monkeypatch,
        repo_json=UNAVAILABLE_REPO_JSON,
        vuln_alerts_enabled=False,
        pvr_json=None,
        dry_run=True,
    )
    assert (await worker(REPO)).status == Status.LIMITED


async def test_security_worker_apply_unchanged_when_already_fully_enabled(monkeypatch):
    worker = _security_worker(
        monkeypatch,
        repo_json=FULLY_ENABLED_REPO_JSON,
        vuln_alerts_enabled=True,
        pvr_json={"enabled": True},
        codeql_json=CONFIGURED_CODEQL_JSON,
        dry_run=False,
        api_responses=[
            _FakeResponse(200),
            _FakeResponse(204),
            _FakeResponse(200),
            _FakeResponse(200),
        ],
    )
    result = await worker(REPO)
    assert result.status == Status.UNCHANGED
    assert result.line == f"{'repo':<30} unchanged: enabled"


async def test_security_worker_apply_ok_when_newly_enabled(monkeypatch):
    worker = _security_worker(
        monkeypatch,
        repo_json=FULLY_ENABLED_REPO_JSON,
        vuln_alerts_enabled=False,
        pvr_json={"enabled": True},
        codeql_json=CONFIGURED_CODEQL_JSON,
        dry_run=False,
        api_responses=[
            _FakeResponse(200),
            _FakeResponse(204),
            _FakeResponse(200),
            _FakeResponse(200),
        ],
    )
    assert (await worker(REPO)).status == Status.OK


async def test_security_worker_apply_limited_unchanged_when_unavailable_and_nothing_pending(
    monkeypatch,
):
    worker = _security_worker(
        monkeypatch,
        repo_json=UNAVAILABLE_REPO_JSON,
        vuln_alerts_enabled=True,
        pvr_json=None,
        codeql_json=None,
        dry_run=False,
        api_responses=[
            _FakeResponse(422),
            _FakeResponse(204),
            _FakeResponse(404),
            _FakeResponse(404),
        ],
    )
    assert (await worker(REPO)).status == Status.LIMITED_UNCHANGED


async def test_security_worker_apply_limited_when_unavailable_and_was_pending(
    monkeypatch,
):
    worker = _security_worker(
        monkeypatch,
        repo_json=UNAVAILABLE_REPO_JSON,
        vuln_alerts_enabled=False,
        pvr_json=None,
        codeql_json=None,
        dry_run=False,
        api_responses=[
            _FakeResponse(422),
            _FakeResponse(204),
            _FakeResponse(404),
            _FakeResponse(404),
        ],
    )
    assert (await worker(REPO)).status == Status.LIMITED


async def test_security_worker_apply_reports_code_scanning_unavailable_for_no_supported_language(
    monkeypatch,
):
    worker = _security_worker(
        monkeypatch,
        repo_json=FULLY_ENABLED_REPO_JSON,
        vuln_alerts_enabled=True,
        pvr_json={"enabled": True},
        codeql_json=None,
        dry_run=False,
        api_responses=[
            _FakeResponse(200),
            _FakeResponse(204),
            _FakeResponse(200),
            _FakeResponse(422),
        ],
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    assert "code scanning" in result.line


async def test_security_worker_apply_disables_dependabot_via_dedicated_endpoint(
    monkeypatch,
):
    calls = []
    worker = _security_worker(
        monkeypatch,
        repo_json=UNAVAILABLE_REPO_JSON,
        vuln_alerts_enabled=True,
        pvr_json=None,
        codeql_json=None,
        dry_run=False,
        api_responses=[
            _FakeResponse(422),
            _FakeResponse(204),
            _FakeResponse(404),
            _FakeResponse(404),
        ],
        calls=calls,
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    patch_body = calls[0][1]["json"]["security_and_analysis"]
    assert "dependabot_security_updates" not in patch_body
    assert calls[1][0] == ("DELETE", "/repos/hugoh/repo/automated-security-fixes")


def _stub_cmd_protection_sync(monkeypatch, *, results=()):
    seen = {}

    async def fake_list_repos(owner, *, only=None, skip=None, require_only_match=False):
        return [REPO]

    async def fake_run_parallel(
        repos, worker, *, verbose=False, jobs=None, dry_run=False
    ):
        seen["verbose"] = verbose
        return list(results)

    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    monkeypatch.setattr(repo_admin, "run_parallel", fake_run_parallel)
    monkeypatch.setattr(repo_admin, "default_branch_protection_exclude", set)
    return seen


async def test_cmd_protection_sync_lists_adopt_renamed_checks_candidates(
    monkeypatch, capsys
):
    _stub_cmd_protection_sync(
        monkeypatch,
        results=[
            repo_admin.RepoResult(
                REPO,
                "repo: kept test / Tests over sampled Tests",
                Status.LIMITED_UNCHANGED,
                tag=protection.Tag.RENAME_CANDIDATE,
            )
        ],
    )
    args = argparse.Namespace(repos=[], skip=None, dry_run=True, verbose=False)
    await repo_admin.cmd_protection_sync(args)
    out = capsys.readouterr().out
    assert "Candidates for --adopt-renamed-checks" in out
    assert out.rstrip().endswith(": repo")
    assert "Would be (with required status checks): 1" in out


async def test_cmd_protection_sync_merges_exclude_list_into_skip(monkeypatch):
    calls, fake_list_repos = _capturing_list_repos_calls()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    monkeypatch.setattr(
        repo_admin, "default_branch_protection_exclude", lambda: {"homebrew-tap"}
    )
    args = argparse.Namespace(repos=[], skip="other-repo", dry_run=True, verbose=False)
    await repo_admin.cmd_protection_sync(args)
    assert calls[0]["skip"] == {"homebrew-tap", "other-repo"}


async def test_cmd_protection_sync_excludes_even_without_explicit_skip(monkeypatch):
    calls, fake_list_repos = _capturing_list_repos_calls()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    monkeypatch.setattr(
        repo_admin, "default_branch_protection_exclude", lambda: {"homebrew-tap"}
    )
    args = argparse.Namespace(repos=[], skip=None, dry_run=True, verbose=False)
    await repo_admin.cmd_protection_sync(args)
    assert calls[0]["skip"] == {"homebrew-tap"}


async def test_cmd_protection_sync_fetches_excluded_repos_to_unprotect(monkeypatch):
    calls, fake_list_repos = _capturing_list_repos_calls()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    monkeypatch.setattr(
        repo_admin, "default_branch_protection_exclude", lambda: {"homebrew-tap"}
    )
    args = argparse.Namespace(repos=[], skip=None, dry_run=True, verbose=False)
    await repo_admin.cmd_protection_sync(args)
    assert {
        "only": {"homebrew-tap"},
        "skip": None,
        "require_only_match": False,
    } in calls


async def test_cmd_protection_sync_does_not_refetch_when_nothing_excluded(monkeypatch):
    calls, fake_list_repos = _capturing_list_repos_calls()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    monkeypatch.setattr(repo_admin, "default_branch_protection_exclude", set)
    args = argparse.Namespace(repos=[], skip=None, dry_run=True, verbose=False)
    await repo_admin.cmd_protection_sync(args)
    assert len(calls) == 1


async def test_cmd_protection_sync_passes_verbose_to_run_parallel(monkeypatch):
    seen = _stub_cmd_protection_sync(monkeypatch, results=[])
    args = argparse.Namespace(repos=[], skip=None, dry_run=True, verbose=True)
    await repo_admin.cmd_protection_sync(args)
    assert seen["verbose"] is True


async def test_cmd_protection_sync_dry_run_reports_plan_gated_skips(
    monkeypatch, capsys
):
    # A dry run must surface which private repos it can't protect due to plan
    # limits -- previously this summary only printed on a real apply, so a
    # dry run gave no indication a repo was silently unfixable.
    _stub_cmd_protection_sync(
        monkeypatch,
        results=[
            repo_admin.RepoResult(
                REPO,
                "repo: skipped",
                Status.LIMITED_UNCHANGED,
                tag=protection.Tag.SKIPPED_NO_PLAN,
            )
        ],
    )
    args = argparse.Namespace(repos=[], skip=None, dry_run=True, verbose=False)
    await repo_admin.cmd_protection_sync(args)
    out = capsys.readouterr().out
    assert "Summary:" in out
    assert (
        "Skipped (plan doesn't allow branch protection on private repos): repo" in out
    )


async def test_cmd_protection_sync_unprotects_excluded_repos_and_reports_them(
    monkeypatch, capsys
):
    async def fake_list_repos(owner, *, only=None, skip=None, require_only_match=False):
        return [REPO] if only == {"homebrew-tap"} else []

    call_count = 0

    async def fake_run_parallel(
        repos, worker, *, verbose=False, jobs=None, dry_run=False
    ):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return []
        result = await worker(REPO)
        return [result]

    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    monkeypatch.setattr(repo_admin, "run_parallel", fake_run_parallel)
    monkeypatch.setattr(
        repo_admin, "default_branch_protection_exclude", lambda: {"homebrew-tap"}
    )

    async def fake_api_raw(method, *a, **k):
        return _FakeResponse(200)

    monkeypatch.setattr(protection, "api_raw", fake_api_raw)
    args = argparse.Namespace(repos=[], skip=None, dry_run=False, verbose=False)
    await repo_admin.cmd_protection_sync(args)
    out = capsys.readouterr().out
    assert "Removed branch protection (branch-protection-exclude.yaml): repo" in out


# ---------------------------------------------------------------------------
# sync (meta)
# ---------------------------------------------------------------------------


async def test_cmd_sync_runs_squash_title_after_protection(monkeypatch):
    calls = []

    def recorder(name):
        async def fake(args):
            calls.append(name)
            return 0

        return fake

    monkeypatch.setattr(repo_admin, "_merge_settings_sync", recorder("merge-settings"))
    monkeypatch.setattr(repo_admin, "_features_sync", recorder("features"))
    monkeypatch.setattr(
        repo_admin, "cmd_protection_sync", recorder("branch-protection")
    )
    monkeypatch.setattr(repo_admin, "_squash_title_sync", recorder("squash-title"))
    monkeypatch.setattr(repo_admin, "cmd_security_sync", recorder("security-features"))
    monkeypatch.setattr(repo_admin, "cmd_pages_sync", recorder("pages"))
    args = argparse.Namespace(dry_run=True, repos=[], skip=None, verbose=False)
    assert await repo_admin.cmd_sync(args) == 0
    assert calls == [
        "merge-settings",
        "features",
        "branch-protection",
        "squash-title",
        "security-features",
        "pages",
    ]


async def test_cmd_sync_continues_after_a_command_fails_and_returns_nonzero(
    monkeypatch,
):
    calls = []

    async def failing(args):
        calls.append("merge-settings")
        raise GhError("boom")

    async def fake_branch_protection(args):
        calls.append("branch-protection")
        return 0

    async def fake_features(args):
        calls.append("features")
        return 0

    async def fake_squash_title(args):
        calls.append("squash-title")
        return 0

    async def fake_security_features(args):
        calls.append("security-features")
        return 0

    monkeypatch.setattr(repo_admin, "_merge_settings_sync", failing)
    monkeypatch.setattr(repo_admin, "_features_sync", fake_features)
    monkeypatch.setattr(repo_admin, "_squash_title_sync", fake_squash_title)
    monkeypatch.setattr(repo_admin, "cmd_protection_sync", fake_branch_protection)
    monkeypatch.setattr(repo_admin, "cmd_security_sync", fake_security_features)
    args = argparse.Namespace(dry_run=True, repos=[], skip=None, verbose=False)
    assert await repo_admin.cmd_sync(args) == 1
    assert calls == [
        "merge-settings",
        "features",
        "branch-protection",
        "squash-title",
        "security-features",
    ]


async def test_cmd_sync_returns_nonzero_when_a_command_returns_nonzero(monkeypatch):
    async def fake_one(args):
        return 1

    async def fake_zero(args):
        return 0

    monkeypatch.setattr(repo_admin, "_merge_settings_sync", fake_one)
    monkeypatch.setattr(repo_admin, "_features_sync", fake_zero)
    monkeypatch.setattr(repo_admin, "_squash_title_sync", fake_zero)
    monkeypatch.setattr(repo_admin, "cmd_protection_sync", fake_zero)
    monkeypatch.setattr(repo_admin, "cmd_security_sync", fake_zero)
    args = argparse.Namespace(dry_run=True, repos=[], skip=None, verbose=False)
    assert await repo_admin.cmd_sync(args) == 1


async def test_cmd_sync_runs_pages_sync_last_for_mapped_repos_only(monkeypatch):
    seen = []

    async def fake_zero(args):
        return 0

    async def fake_pages(args):
        seen.append(args.repos)
        return 0

    monkeypatch.setattr(repo_admin, "_merge_settings_sync", fake_zero)
    monkeypatch.setattr(repo_admin, "_features_sync", fake_zero)
    monkeypatch.setattr(repo_admin, "_squash_title_sync", fake_zero)
    monkeypatch.setattr(repo_admin, "cmd_protection_sync", fake_zero)
    monkeypatch.setattr(repo_admin, "cmd_security_sync", fake_zero)
    monkeypatch.setattr(repo_admin, "cmd_pages_sync", fake_pages)
    monkeypatch.setattr(
        repo_admin.lib, "default_pages_domains", lambda: {"awesome-jj": DOMAIN}
    )
    args = argparse.Namespace(
        dry_run=True, repos=["awesome-jj", "other"], skip=None, verbose=False
    )
    assert await repo_admin.cmd_sync(args) == 0
    assert seen == [["awesome-jj"]]

    seen.clear()
    args = argparse.Namespace(dry_run=True, repos=["other"], skip=None, verbose=False)
    assert await repo_admin.cmd_sync(args) == 0
    assert seen == []


def test_sync_subcommand_is_registered_in_parser():
    args = repo_admin.build_parser().parse_args(["sync", "--dry-run"])
    assert args.func == repo_admin.cmd_sync
    assert args.dry_run is True


def test_short_flags_match_long_flags():
    parse = repo_admin.build_parser().parse_args
    a = parse(["protection", "sync", "-n", "-v", "-s", "x", "-c", "-a"])
    assert (a.dry_run, a.verbose, a.skip) == (True, True, "x")
    assert a.clear_stale_checks and a.adopt_renamed_checks
    assert parse(["pages", "sync", "-e"]).enable is True
    assert parse(["pages", "config", "-d", "larve.net"]).domain == "larve.net"
    assert parse(["secrets", "sync", "-S", "a"]).secret == "a"
    assert parse(["variables", "sync", "-V", "a"]).variable == "a"
    b = parse(["activity", "-w", "3", "-H", "7", "-l", "5"])
    assert (b.window_months, b.half_life_days, b.limit) == (3, 7, 5)


# ---------------------------------------------------------------------------
# pages sync
# ---------------------------------------------------------------------------

DOMAIN = "awesome-jj.larve.net"

PAGES_REPO = Repo(
    name="repo",
    default_branch="main",
    is_private=False,
    is_fork=False,
    homepage=f"https://{DOMAIN}",
)


def test_pages_domain_up_to_date_true_when_cname_and_https_match():
    assert repo_admin.pages_domain_up_to_date(
        {"cname": DOMAIN, "https_enforced": True}, DOMAIN
    )


def test_pages_domain_up_to_date_false_when_cname_differs():
    assert not repo_admin.pages_domain_up_to_date(
        {"cname": "other.larve.net", "https_enforced": True}, DOMAIN
    )


def test_pages_domain_up_to_date_false_when_https_not_enforced():
    assert not repo_admin.pages_domain_up_to_date(
        {"cname": DOMAIN, "https_enforced": False}, DOMAIN
    )


def test_pages_domain_https_ready_true_when_cert_approved():
    assert repo_admin.pages_domain_https_ready(
        {"https_certificate": {"state": "approved"}}
    )


def test_pages_domain_https_ready_false_when_cert_pending():
    assert not repo_admin.pages_domain_https_ready(
        {"https_certificate": {"state": "pending"}}
    )


def test_pages_domain_https_ready_false_when_no_certificate():
    assert not repo_admin.pages_domain_https_ready({})


def test_pages_domain_dry_run_line_unchanged():
    current = {"cname": DOMAIN, "https_enforced": True}
    line = repo_admin.pages_domain_dry_run_line(
        "repo", current, DOMAIN, Status.UNCHANGED
    )
    assert line == f"{'repo':<30} unchanged: cname={DOMAIN}, https enforced"


def test_pages_domain_dry_run_line_would_set_cname():
    current = {"cname": None, "https_enforced": False}
    line = repo_admin.pages_domain_dry_run_line("repo", current, DOMAIN, Status.OK)
    assert line == f"{'repo':<30} would set cname -> {DOMAIN}"


def test_pages_domain_dry_run_line_would_enable_https():
    current = {
        "cname": DOMAIN,
        "https_enforced": False,
        "https_certificate": {"state": "approved"},
    }
    line = repo_admin.pages_domain_dry_run_line("repo", current, DOMAIN, Status.OK)
    assert line == f"{'repo':<30} cname={DOMAIN}; would enable https_enforced"


def test_pages_domain_dry_run_line_cert_pending():
    current = {
        "cname": DOMAIN,
        "https_enforced": False,
        "https_certificate": {"state": "pending"},
    }
    line = repo_admin.pages_domain_dry_run_line(
        "repo", current, DOMAIN, Status.LIMITED_UNCHANGED
    )
    assert line == f"{'repo':<30} unchanged: cname={DOMAIN}; https cert pending"


def test_pages_domain_apply_line_unchanged_https_enforced():
    settings = {"cname": DOMAIN, "https_enforced": True}
    line = repo_admin.pages_domain_apply_line(
        "repo", settings, settings, DOMAIN, Status.UNCHANGED
    )
    assert line == f"{'repo':<30} unchanged: cname={DOMAIN}, https enforced"


def test_pages_domain_apply_line_unchanged_cert_pending():
    settings = {"cname": DOMAIN, "https_enforced": False}
    line = repo_admin.pages_domain_apply_line(
        "repo", settings, settings, DOMAIN, Status.LIMITED_UNCHANGED
    )
    assert line == f"{'repo':<30} unchanged: cname={DOMAIN}; https cert pending"


def test_pages_domain_apply_line_cname_changed():
    before = {"cname": None, "https_enforced": False}
    after = {"cname": DOMAIN, "https_enforced": False}
    line = repo_admin.pages_domain_apply_line("repo", before, after, DOMAIN, Status.OK)
    assert line == f"{'repo':<30} cname -> {DOMAIN}"


def test_pages_domain_apply_line_https_enabled():
    before = {"cname": DOMAIN, "https_enforced": False}
    after = {"cname": DOMAIN, "https_enforced": True}
    line = repo_admin.pages_domain_apply_line("repo", before, after, DOMAIN, Status.OK)
    assert line == f"{'repo':<30} https_enforced -> true"


def _pages_domain_dry_run_worker(monkeypatch, pages_config):
    async def fake_pages_config(owner, name):
        return pages_config

    monkeypatch.setattr(repo_admin, "_pages_config", fake_pages_config)
    return repo_admin.make_pages_domain_worker(
        owner="hugoh", dry_run=True, domains={"repo": DOMAIN}
    )


async def test_pages_domain_worker_dry_run_unchanged(monkeypatch):
    worker = _pages_domain_dry_run_worker(
        monkeypatch, {"cname": DOMAIN, "https_enforced": True}
    )
    result = await worker(PAGES_REPO)
    assert result.status == Status.UNCHANGED


async def test_pages_domain_worker_dry_run_would_set_cname(monkeypatch):
    worker = _pages_domain_dry_run_worker(
        monkeypatch, {"cname": None, "https_enforced": False}
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED
    assert "would set cname" in result.line


async def test_pages_domain_worker_dry_run_limited_unchanged_when_cert_pending(
    monkeypatch,
):
    worker = _pages_domain_dry_run_worker(
        monkeypatch,
        {
            "cname": DOMAIN,
            "https_enforced": False,
            "https_certificate": {"state": "pending"},
        },
    )
    result = await worker(PAGES_REPO)
    assert result.status == Status.LIMITED_UNCHANGED


async def test_pages_domain_worker_dry_run_flags_homepage_mismatch(monkeypatch):
    worker = _pages_domain_dry_run_worker(
        monkeypatch, {"cname": DOMAIN, "https_enforced": True}
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED
    assert f"would set homepage -> https://{DOMAIN}" in result.line


async def test_pages_domain_worker_apply_sets_homepage(monkeypatch):
    worker, calls = _pages_domain_apply_worker(
        monkeypatch,
        [
            {"cname": DOMAIN, "https_enforced": True},
            {"cname": DOMAIN, "https_enforced": True},
        ],
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert calls == [("PATCH", "/repos/hugoh/repo", {"homepage": f"https://{DOMAIN}"})]
    assert f"homepage -> https://{DOMAIN}" in result.line


def _pages_domain_apply_worker(monkeypatch, responses):
    calls = []
    response_iter = iter(responses)

    async def fake_pages_config(owner, name):
        return next(response_iter)

    async def fake_api_json(method, path, **kwargs):
        calls.append((method, path, kwargs.get("json")))
        return {}

    monkeypatch.setattr(repo_admin, "_pages_config", fake_pages_config)
    monkeypatch.setattr(repo_admin, "api_json", fake_api_json)
    worker = repo_admin.make_pages_domain_worker(
        owner="hugoh", dry_run=False, domains={"repo": DOMAIN}
    )
    return worker, calls


async def test_pages_domain_worker_apply_sets_cname(monkeypatch):
    worker, calls = _pages_domain_apply_worker(
        monkeypatch,
        [
            {"cname": None, "https_enforced": False},
            {"cname": DOMAIN, "https_enforced": False},
        ],
    )
    result = await worker(PAGES_REPO)
    assert result.status == Status.LIMITED
    assert calls == [("PUT", "/repos/hugoh/repo/pages", {"cname": DOMAIN})]


async def test_pages_domain_worker_apply_enables_https_when_cert_ready(monkeypatch):
    worker, calls = _pages_domain_apply_worker(
        monkeypatch,
        [
            {
                "cname": DOMAIN,
                "https_enforced": False,
                "https_certificate": {"state": "approved"},
            },
            {"cname": DOMAIN, "https_enforced": True},
        ],
    )
    result = await worker(PAGES_REPO)
    assert result.status == Status.OK
    assert calls == [("PUT", "/repos/hugoh/repo/pages", {"https_enforced": True})]


async def test_pages_domain_worker_apply_unchanged_when_already_at_target(monkeypatch):
    async def fake_pages_config(owner, name):
        return {"cname": DOMAIN, "https_enforced": True}

    async def fake_api_json(*a, **k):
        raise AssertionError("should not call the API when already at target")

    monkeypatch.setattr(repo_admin, "_pages_config", fake_pages_config)
    monkeypatch.setattr(repo_admin, "api_json", fake_api_json)
    worker = repo_admin.make_pages_domain_worker(
        owner="hugoh", dry_run=False, domains={"repo": DOMAIN}
    )
    result = await worker(PAGES_REPO)
    assert result.status == Status.UNCHANGED


async def test_pages_config_explains_404_as_pages_not_enabled(monkeypatch):
    async def fake_api_raw(method, path, **kwargs):
        return httpx.Response(404, json={"message": "Not Found"})

    monkeypatch.setattr(repo_admin, "api_raw", fake_api_raw)
    with pytest.raises(GhError, match="Pages is not enabled on hugoh/repo"):
        await repo_admin._pages_config("hugoh", "repo")


def _not_enabled_pages_config(monkeypatch):
    async def fake_pages_config(owner, name):
        raise GhError("not enabled", status_code=404)

    monkeypatch.setattr(repo_admin, "_pages_config", fake_pages_config)


async def test_pages_domain_worker_without_enable_fails_when_pages_missing(
    monkeypatch,
):
    _not_enabled_pages_config(monkeypatch)
    worker = repo_admin.make_pages_domain_worker(
        owner="hugoh", dry_run=True, domains={"repo": DOMAIN}
    )
    with pytest.raises(GhError):
        await worker(PAGES_REPO)


async def test_pages_domain_worker_enable_dry_run_reports_would_enable(monkeypatch):
    _not_enabled_pages_config(monkeypatch)
    worker = repo_admin.make_pages_domain_worker(
        owner="hugoh", dry_run=True, domains={"repo": DOMAIN}, enable=True
    )
    result = await worker(PAGES_REPO)
    assert result.status == Status.LIMITED
    assert f"would enable Pages (workflow), set cname -> {DOMAIN}" in result.line


async def test_pages_domain_worker_enable_creates_site_then_sets_cname(monkeypatch):
    configs = iter(
        [
            GhError("not enabled", status_code=404),
            {"cname": None, "https_enforced": False},
            {"cname": DOMAIN, "https_enforced": False},
        ]
    )
    calls = []

    async def fake_pages_config(owner, name):
        value = next(configs)
        if isinstance(value, Exception):
            raise value
        return value

    async def fake_api_json(method, path, json=None):
        calls.append((method, path, json))
        return {}

    monkeypatch.setattr(repo_admin, "_pages_config", fake_pages_config)
    monkeypatch.setattr(repo_admin, "api_json", fake_api_json)
    worker = repo_admin.make_pages_domain_worker(
        owner="hugoh", dry_run=False, domains={"repo": DOMAIN}, enable=True
    )
    result = await worker(PAGES_REPO)
    pages_path = "/repos/hugoh/repo/pages"
    assert calls[:2] == [
        ("POST", pages_path, {"build_type": "workflow"}),
        ("PUT", pages_path, {"cname": DOMAIN}),
    ]
    assert result.status == Status.LIMITED
    assert "enabled Pages (workflow), cname ->" in result.line


def test_pages_sync_enable_flag_is_parsed():
    args = repo_admin.build_parser().parse_args(["pages", "sync", "--enable"])
    assert args.enable is True


async def test_pages_disable_worker_dry_run_and_apply(monkeypatch):
    calls = []

    async def fake_fetch(owner, name):
        return {"cname": DOMAIN}

    async def fake_api_json(method, path, json=None):
        calls.append((method, path))
        return {}

    monkeypatch.setattr(repo_admin, "_fetch_pages_config", fake_fetch)
    monkeypatch.setattr(repo_admin, "api_json", fake_api_json)

    dry = repo_admin.make_pages_disable_worker("hugoh", dry_run=True)
    result = await dry(PAGES_REPO)
    assert result.status == Status.OK
    assert "would disable Pages" in result.line
    assert calls == []

    real = repo_admin.make_pages_disable_worker("hugoh", dry_run=False)
    result = await real(PAGES_REPO)
    assert result.status == Status.OK
    assert calls == [("DELETE", "/repos/hugoh/repo/pages")]


async def test_pages_disable_worker_unchanged_when_already_disabled(monkeypatch):
    async def fake_fetch(owner, name):
        return None

    async def fake_api_json(*a, **k):
        raise AssertionError("should not call the API")

    monkeypatch.setattr(repo_admin, "_fetch_pages_config", fake_fetch)
    monkeypatch.setattr(repo_admin, "api_json", fake_api_json)
    worker = repo_admin.make_pages_disable_worker("hugoh", dry_run=False)
    assert (await worker(PAGES_REPO)).status == Status.UNCHANGED


async def test_pages_unset_url_worker(monkeypatch):
    calls = []

    async def fake_api_json(method, path, json=None):
        calls.append((method, path, json))
        return {}

    monkeypatch.setattr(repo_admin, "api_json", fake_api_json)

    dry = repo_admin.make_pages_unset_url_worker("hugoh", dry_run=True)
    result = await dry(PAGES_REPO)
    assert result.status == Status.OK
    assert f"would clear homepage {PAGES_REPO.homepage}" in result.line
    assert calls == []

    real = repo_admin.make_pages_unset_url_worker("hugoh", dry_run=False)
    assert (await real(PAGES_REPO)).status == Status.OK
    assert calls == [("PATCH", "/repos/hugoh/repo", {"homepage": ""})]

    no_url = Repo(name="repo", default_branch="main", is_private=False, is_fork=False)
    assert (await real(no_url)).status == Status.UNCHANGED
    assert len(calls) == 1


@pytest.mark.parametrize("cmd", ["cmd_pages_disable", "cmd_pages_unset_url"])
async def test_pages_teardown_commands_require_unmapped_repos(monkeypatch, capsys, cmd):
    monkeypatch.setattr(
        repo_admin.lib, "default_pages_domains", lambda: {"awesome-jj": DOMAIN}
    )
    fn = getattr(repo_admin, cmd)
    for repos in ([], ["awesome-jj"]):
        args = argparse.Namespace(dry_run=True, repos=repos, skip=None, verbose=False)
        assert await fn(args) == 1
    assert "awesome-jj" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("verb", "func"),
    [("disable", "cmd_pages_disable"), ("unset-url", "cmd_pages_unset_url")],
)
def test_pages_teardown_subcommands_are_registered(verb, func):
    args = repo_admin.build_parser().parse_args(["pages", verb, "r", "--dry-run"])
    assert args.func == getattr(repo_admin, func)
    assert args.repos == ["r"]


async def test_cmd_pages_sync_defaults_to_mapped_repos(monkeypatch):
    monkeypatch.setattr(
        repo_admin.lib, "default_pages_domains", lambda: {"awesome-jj": DOMAIN}
    )
    seen, fake_list_repos = _capturing_list_repos()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    args = argparse.Namespace(dry_run=True, repos=[], skip=None, verbose=False)
    assert await repo_admin.cmd_pages_sync(args) == 0
    assert seen == {
        "only": {"awesome-jj"},
        "skip": None,
        "require_only_match": False,
    }


async def test_cmd_pages_sync_errors_on_unmapped_repo(monkeypatch, capsys):
    monkeypatch.setattr(
        repo_admin.lib, "default_pages_domains", lambda: {"awesome-jj": DOMAIN}
    )
    args = argparse.Namespace(
        dry_run=True, repos=["not-mapped"], skip=None, verbose=False
    )
    assert await repo_admin.cmd_pages_sync(args) == 1
    assert "not-mapped" in capsys.readouterr().err


def test_pages_sync_subcommand_is_registered_in_parser():
    args = repo_admin.build_parser().parse_args(["pages", "sync", "--dry-run"])
    assert args.func == repo_admin.cmd_pages_sync
    assert args.dry_run is True


# ---------------------------------------------------------------------------
# pages status
# ---------------------------------------------------------------------------


async def test_cmd_pages_status_lists_enabled_repos_and_flags_unmapped(
    monkeypatch, capsys
):
    mapped_repo = Repo(
        name="awesome-jj",
        default_branch="main",
        is_private=False,
        is_fork=False,
        homepage=f"https://{DOMAIN}",
    )
    unmapped_repo = Repo(
        name="other-repo", default_branch="main", is_private=False, is_fork=False
    )
    disabled_repo = Repo(
        name="no-pages", default_branch="main", is_private=False, is_fork=False
    )

    async def fake_list_repos(owner, *, only=None, skip=None, require_only_match=False):
        return [mapped_repo, unmapped_repo, disabled_repo]

    pages_configs = {
        "awesome-jj": _FakeResponseWithJson(
            200,
            {
                "cname": DOMAIN,
                "https_enforced": True,
                "html_url": f"https://{DOMAIN}",
            },
        ),
        "other-repo": _FakeResponseWithJson(
            200,
            {
                "cname": None,
                "https_enforced": False,
                "html_url": "https://hugoh.github.io/other-repo/",
            },
        ),
        "no-pages": _FakeResponseWithJson(404, {}),
    }

    async def fake_api_raw(method, path, **kwargs):
        name = path.split("/")[3]
        return pages_configs[name]

    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    monkeypatch.setattr(repo_admin, "api_raw", fake_api_raw)
    monkeypatch.setattr(
        repo_admin.lib, "default_pages_domains", lambda: {"awesome-jj": DOMAIN}
    )

    args = argparse.Namespace(repos=[], skip=None)
    assert await repo_admin.cmd_pages_status(args) == 0
    out = capsys.readouterr().out
    assert "awesome-jj" in out
    assert "other-repo" in out
    assert "no-pages" not in out
    assert f"https://{DOMAIN}" in out
    assert "https://hugoh.github.io/other-repo/" in out
    assert "not in config/pages-domains.yaml" in out
    assert "other-repo" in out.split("not in config/pages-domains.yaml")[1]
    assert "HOMEPAGE" in out
    assert "(none)" in out


def test_pages_status_subcommand_is_registered_in_parser():
    args = repo_admin.build_parser().parse_args(["pages", "status"])
    assert args.func == repo_admin.cmd_pages_status


# ---------------------------------------------------------------------------
# pages config
# ---------------------------------------------------------------------------


def test_pages_domain_suggest_appends_domain():
    assert repo_admin.pages_domain_suggest("awesome-jj", "larve.net") == (
        "awesome-jj.larve.net"
    )


def test_pages_domain_suggest_replaces_dots_in_repo_name_with_dashes():
    assert repo_admin.pages_domain_suggest("AppBadgeWatcher.spoon", "larve.net") == (
        "AppBadgeWatcher-spoon.larve.net"
    )


async def test_cmd_pages_config_uses_explicit_repos_without_api_calls(
    monkeypatch, capsys
):
    async def fail_list_repos(*a, **k):
        raise AssertionError("should not query GitHub when --only is given")

    monkeypatch.setattr(repo_admin, "list_repos", fail_list_repos)
    args = argparse.Namespace(
        domain="larve.net", repos=["awesome-jj", "hrd"], skip=None
    )
    assert await repo_admin.cmd_pages_config(args) == 0
    out = capsys.readouterr().out
    assert "awesome-jj: awesome-jj.larve.net" in out
    assert "hrd: hrd.larve.net" in out


async def test_cmd_pages_config_auto_discovers_unmapped_enabled_repos(
    monkeypatch, capsys
):
    mapped_repo = Repo(
        name="awesome-jj", default_branch="main", is_private=False, is_fork=False
    )
    unmapped_repo = Repo(
        name="AppBadgeWatcher.spoon",
        default_branch="main",
        is_private=False,
        is_fork=False,
    )

    async def fake_list_repos(owner, *, only=None, skip=None, require_only_match=False):
        return [mapped_repo, unmapped_repo]

    async def fake_pages_enabled_repos(repos):
        return [
            (mapped_repo, {"cname": DOMAIN}),
            (unmapped_repo, {"cname": None}),
        ]

    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    monkeypatch.setattr(repo_admin, "_pages_enabled_repos", fake_pages_enabled_repos)
    monkeypatch.setattr(
        repo_admin.lib, "default_pages_domains", lambda: {"awesome-jj": DOMAIN}
    )

    args = argparse.Namespace(domain="larve.net", repos=[], skip=None)
    assert await repo_admin.cmd_pages_config(args) == 0
    out = capsys.readouterr().out
    assert "AppBadgeWatcher-spoon.larve.net" in out
    assert "awesome-jj" not in out


def test_pages_config_subcommand_is_registered_in_parser():
    args = repo_admin.build_parser().parse_args(
        ["pages", "config", "--domain", "larve.net"]
    )
    assert args.func == repo_admin.cmd_pages_config
    assert args.domain == "larve.net"


# ---------------------------------------------------------------------------
# secrets sync
# ---------------------------------------------------------------------------


def test_secrets_sync_line_dry_run():
    assert repo_admin.secrets_sync_line("NAME", "repo", dry_run=True) == (
        f"{'repo':<30} would set NAME"
    )


def test_secrets_sync_line_apply():
    assert repo_admin.secrets_sync_line("NAME", "repo", dry_run=False) == (
        f"{'repo':<30} set NAME"
    )


async def test_secrets_sync_worker_dry_run_does_not_call_set_repo_secret(monkeypatch):
    async def fail_set_repo_secret(*a, **k):
        raise AssertionError("dry-run should not call set_repo_secret")

    monkeypatch.setattr(repo_admin.lib, "set_repo_secret", fail_set_repo_secret)
    worker = repo_admin.make_secrets_sync_worker(
        owner="hugoh", dry_run=True, secret_name="NAME", value="the-value"
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert "would set NAME" in result.line


async def test_secrets_sync_worker_apply_calls_set_repo_secret(monkeypatch):
    calls = []

    async def fake_set_repo_secret(owner, repo_name, secret_name, value):
        calls.append((owner, repo_name, secret_name, value))

    monkeypatch.setattr(repo_admin.lib, "set_repo_secret", fake_set_repo_secret)
    worker = repo_admin.make_secrets_sync_worker(
        owner="hugoh", dry_run=False, secret_name="NAME", value="the-value"
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert calls == [("hugoh", "repo", "NAME", "the-value")]


def _recording_list_repos():
    seen_only = []

    async def fake_list_repos(owner, *, only=None, skip=None, require_only_match=False):
        seen_only.append(only)
        return []

    return seen_only, fake_list_repos


def _binding(repos, value):
    return {"repos": list(repos), "value": value}


async def test_cmd_secrets_sync_defaults_to_all_configured_secrets(monkeypatch):
    monkeypatch.setattr(
        repo_admin.lib,
        "load_secrets",
        lambda: {
            "NAME_A": [_binding(["repo-a"], "va")],
            "NAME_B": [_binding(["repo-b"], "vb")],
        },
    )
    seen_only, fake_list_repos = _recording_list_repos()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    args = argparse.Namespace(
        dry_run=False, repos=[], skip=None, secret=None, verbose=False
    )
    assert await repo_admin.cmd_secrets_sync(args) == 0
    assert sorted(seen_only, key=str) == [{"repo-a"}, {"repo-b"}]


async def test_cmd_secrets_sync_pushes_each_binding_with_its_own_value(monkeypatch):
    monkeypatch.setattr(
        repo_admin.lib,
        "load_secrets",
        lambda: {
            "GIST_TOKEN": [
                _binding(["config"], "tok-config"),
                _binding(["gh-digest"], "tok-digest"),
            ]
        },
    )

    async def fake_list_repos(owner, *, only=None, skip=None, require_only_match=False):
        return [
            Repo(name=n, default_branch="main", is_private=False, is_fork=False)
            for n in sorted(only or [])
        ]

    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    calls = []

    async def fake_set_repo_secret(owner, repo_name, secret_name, value):
        calls.append((repo_name, value))

    monkeypatch.setattr(repo_admin.lib, "set_repo_secret", fake_set_repo_secret)
    args = argparse.Namespace(
        dry_run=False, repos=[], skip=None, secret=None, verbose=False
    )
    assert await repo_admin.cmd_secrets_sync(args) == 0
    assert sorted(calls) == [("config", "tok-config"), ("gh-digest", "tok-digest")]


async def test_cmd_secrets_sync_skips_secret_when_filters_leave_no_repos(monkeypatch):
    monkeypatch.setattr(
        repo_admin.lib, "load_secrets", lambda: {"NAME_A": [_binding(["repo-a"], "va")]}
    )

    async def fake_list_repos(owner, *, only=None, skip=None, require_only_match=False):
        raise AssertionError(
            "must not call list_repos when the target repo set is empty"
        )

    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    args = argparse.Namespace(
        dry_run=False, repos=[], skip="repo-a", secret=None, verbose=False
    )
    assert await repo_admin.cmd_secrets_sync(args) == 0


async def test_cmd_secrets_sync_errors_on_unknown_secret_name(monkeypatch, capsys):
    monkeypatch.setattr(
        repo_admin.lib, "load_secrets", lambda: {"NAME_A": [_binding(["repo-a"], "va")]}
    )
    args = argparse.Namespace(
        dry_run=True, repos=[], skip=None, secret="NOT_CONFIGURED", verbose=False
    )
    assert await repo_admin.cmd_secrets_sync(args) == 1
    assert "NOT_CONFIGURED" in capsys.readouterr().err


async def test_cmd_secrets_sync_only_filters_within_each_binding(monkeypatch):
    monkeypatch.setattr(
        repo_admin.lib,
        "load_secrets",
        lambda: {
            "NAME_A": [_binding(["repo-a", "repo-shared"], "va")],
            "NAME_B": [_binding(["repo-b", "repo-shared"], "vb")],
        },
    )
    seen_only, fake_list_repos = _recording_list_repos()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    args = argparse.Namespace(
        dry_run=False, repos=["repo-shared"], skip=None, secret=None, verbose=False
    )
    assert await repo_admin.cmd_secrets_sync(args) == 0
    assert sorted(seen_only, key=str) == [{"repo-shared"}, {"repo-shared"}]


async def test_cmd_secrets_sync_errors_on_empty_value(monkeypatch, capsys):
    monkeypatch.setattr(
        repo_admin.lib,
        "load_secrets",
        lambda: {
            "NAME_A": [_binding(["repo-a"], "")],
            "NAME_B": [_binding(["repo-b"], "vb")],
        },
    )
    processed, fake_list_repos = _recording_list_repos()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    args = argparse.Namespace(
        dry_run=False, repos=[], skip=None, secret=None, verbose=False
    )
    assert await repo_admin.cmd_secrets_sync(args) == 1
    assert "NAME_A" in capsys.readouterr().err
    assert processed == [{"repo-b"}]


async def test_cmd_secrets_sync_dry_run_still_reads_the_mapping(monkeypatch):
    monkeypatch.setattr(
        repo_admin.lib, "load_secrets", lambda: {"NAME_A": [_binding(["repo-a"], "")]}
    )
    seen_only, fake_list_repos = _recording_list_repos()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)

    async def fail_set(*a, **k):
        raise AssertionError("dry-run must not call set_repo_secret")

    monkeypatch.setattr(repo_admin.lib, "set_repo_secret", fail_set)
    args = argparse.Namespace(
        dry_run=True, repos=[], skip=None, secret=None, verbose=False
    )
    assert await repo_admin.cmd_secrets_sync(args) == 0
    assert seen_only == [{"repo-a"}]


def _count_default_owner_calls(monkeypatch):
    calls = []
    real_default_owner = repo_admin.default_owner

    async def counting_default_owner():
        calls.append(1)
        return await real_default_owner()

    monkeypatch.setattr(repo_admin, "default_owner", counting_default_owner)
    return calls


async def test_cmd_secrets_sync_resolves_owner_once(monkeypatch):
    monkeypatch.setattr(
        repo_admin.lib, "load_secrets", lambda: {"NAME_A": [_binding(["repo-a"], "va")]}
    )
    _, fake_list_repos = _recording_list_repos()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    calls = _count_default_owner_calls(monkeypatch)
    args = argparse.Namespace(
        dry_run=False, repos=[], skip=None, secret=None, verbose=False
    )
    assert await repo_admin.cmd_secrets_sync(args) == 0
    assert calls == [1]


def test_secrets_sync_subcommand_is_registered_in_parser():
    args = repo_admin.build_parser().parse_args(
        ["secrets", "sync", "--dry-run", "--secret", "NAME"]
    )
    assert args.func == repo_admin.cmd_secrets_sync
    assert args.secret == "NAME"


# ---------------------------------------------------------------------------
# secrets edit
# ---------------------------------------------------------------------------


def test_secrets_edit_template_seeds_empty_values_for_each_name():
    assert repo_admin.secrets_edit_template({"NAME_B", "NAME_A"}) == (
        "NAME_A: ''\nNAME_B: ''\n"
    )


async def test_cmd_secrets_edit_seeds_example_when_file_missing(monkeypatch):
    monkeypatch.setattr(repo_admin.lib, "SECRETS_ENC_FILE", _MissingPath())
    seeded = []
    monkeypatch.setattr(repo_admin.lib, "init_secrets_file", seeded.append)
    monkeypatch.setattr(repo_admin.lib, "edit_secrets_file", lambda: 0)
    monkeypatch.setattr(repo_admin.lib, "load_secrets", dict)

    assert await repo_admin.cmd_secrets_edit(argparse.Namespace()) == 0
    assert seeded == [repo_admin._SECRETS_EDIT_EXAMPLE]


async def test_cmd_secrets_edit_does_not_seed_when_file_present(monkeypatch):
    monkeypatch.setattr(repo_admin.lib, "SECRETS_ENC_FILE", _PresentPath())

    def fail_init(*a, **k):
        raise AssertionError("should not seed when the file already exists")

    monkeypatch.setattr(repo_admin.lib, "init_secrets_file", fail_init)
    monkeypatch.setattr(repo_admin.lib, "edit_secrets_file", lambda: 0)
    monkeypatch.setattr(repo_admin.lib, "load_secrets", lambda: {"N": []})

    assert await repo_admin.cmd_secrets_edit(argparse.Namespace()) == 0


async def test_cmd_secrets_edit_returns_error_when_sops_exits_nonzero(
    monkeypatch, capsys
):
    monkeypatch.setattr(repo_admin.lib, "SECRETS_ENC_FILE", _PresentPath())
    monkeypatch.setattr(repo_admin.lib, "edit_secrets_file", lambda: 1)

    def fail_load():
        raise AssertionError("should not re-parse when the edit itself failed")

    monkeypatch.setattr(repo_admin.lib, "load_secrets", fail_load)

    assert await repo_admin.cmd_secrets_edit(argparse.Namespace()) == 1
    assert "sops" in capsys.readouterr().err


async def test_cmd_secrets_edit_warns_about_a_malformed_binding(monkeypatch, capsys):
    monkeypatch.setattr(repo_admin.lib, "SECRETS_ENC_FILE", _PresentPath())
    monkeypatch.setattr(repo_admin.lib, "edit_secrets_file", lambda: 0)

    def bad_load():
        raise GhError("NAME in secrets.enc.yaml: expected a list of {repos, value}")

    monkeypatch.setattr(repo_admin.lib, "load_secrets", bad_load)

    assert await repo_admin.cmd_secrets_edit(argparse.Namespace()) == 0
    assert "expected a list" in capsys.readouterr().err


def test_secrets_edit_subcommand_is_registered_in_parser():
    args = repo_admin.build_parser().parse_args(["secrets", "edit"])
    assert args.func == repo_admin.cmd_secrets_edit


# ---------------------------------------------------------------------------
# variables sync / edit
# ---------------------------------------------------------------------------


async def test_variables_sync_worker_apply_calls_set_repo_variable(monkeypatch):
    calls = []

    async def fake_set_repo_variable(owner, repo_name, name, value):
        calls.append((owner, repo_name, name, value))

    monkeypatch.setattr(repo_admin.lib, "set_repo_variable", fake_set_repo_variable)
    worker = repo_admin.make_variables_sync_worker(
        owner="hugoh", dry_run=False, name="SMTP_HOST", value="mail.example"
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert calls == [("hugoh", "repo", "SMTP_HOST", "mail.example")]


async def test_variables_sync_worker_dry_run_does_not_call_set_repo_variable(
    monkeypatch,
):
    async def fail(*a, **k):
        raise AssertionError("dry-run must not call set_repo_variable")

    monkeypatch.setattr(repo_admin.lib, "set_repo_variable", fail)
    worker = repo_admin.make_variables_sync_worker(
        owner="hugoh", dry_run=True, name="SMTP_HOST", value="x"
    )
    result = await worker(REPO)
    assert "would set SMTP_HOST" in result.line


async def test_cmd_variables_sync_defaults_to_all_configured_variables(monkeypatch):
    monkeypatch.setattr(
        repo_admin.lib, "default_variables", lambda: {"A": ["repo-a"], "B": ["repo-b"]}
    )
    monkeypatch.setattr(
        repo_admin.lib, "decrypt_variables", lambda: {"A": "1", "B": "2"}
    )
    seen_only, fake_list_repos = _recording_list_repos()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    args = argparse.Namespace(
        dry_run=False, repos=[], skip=None, variable=None, verbose=False
    )
    assert await repo_admin.cmd_variables_sync(args) == 0
    assert sorted(seen_only, key=str) == [{"repo-a"}, {"repo-b"}]


async def test_cmd_variables_sync_errors_on_unknown_variable_name(monkeypatch, capsys):
    monkeypatch.setattr(repo_admin.lib, "default_variables", lambda: {"A": ["repo-a"]})
    args = argparse.Namespace(
        dry_run=True, repos=[], skip=None, variable="NOPE", verbose=False
    )
    assert await repo_admin.cmd_variables_sync(args) == 1
    err = capsys.readouterr().err
    assert "NOPE" in err
    assert "config/variables.yaml" in err


async def test_cmd_variables_sync_resolves_owner_once(monkeypatch):
    monkeypatch.setattr(repo_admin.lib, "default_variables", lambda: {"A": ["repo-a"]})
    monkeypatch.setattr(repo_admin.lib, "decrypt_variables", lambda: {"A": "1"})
    _, fake_list_repos = _recording_list_repos()
    monkeypatch.setattr(repo_admin, "list_repos", fake_list_repos)
    calls = _count_default_owner_calls(monkeypatch)
    args = argparse.Namespace(
        dry_run=False, repos=[], skip=None, variable=None, verbose=False
    )
    assert await repo_admin.cmd_variables_sync(args) == 0
    assert calls == [1]


def test_variables_sync_subcommand_is_registered_in_parser():
    args = repo_admin.build_parser().parse_args(
        ["variables", "sync", "--dry-run", "--variable", "SMTP_HOST"]
    )
    assert args.func == repo_admin.cmd_variables_sync
    assert args.variable == "SMTP_HOST"


def test_variables_edit_subcommand_is_registered_in_parser():
    args = repo_admin.build_parser().parse_args(["variables", "edit"])
    assert args.func == repo_admin.cmd_variables_edit


async def test_cmd_variables_edit_seeds_variables_enc_file_when_missing(monkeypatch):
    monkeypatch.setattr(
        repo_admin.lib, "default_variables", lambda: {"SMTP_HOST": ["r"]}
    )
    monkeypatch.setattr(repo_admin.lib, "VARIABLES_ENC_FILE", _MissingPath())
    seeded = []
    monkeypatch.setattr(repo_admin.lib, "init_variables_file", seeded.append)
    monkeypatch.setattr(repo_admin.lib, "edit_variables_file", lambda: 0)
    monkeypatch.setattr(repo_admin.lib, "decrypt_variables", lambda: {"SMTP_HOST": "v"})
    assert await repo_admin.cmd_variables_edit(argparse.Namespace()) == 0
    assert seeded == ["SMTP_HOST: ''\n"]


# ---------------------------------------------------------------------------
# config bootstrap
# ---------------------------------------------------------------------------


def test_add_repo_to_config_map_appends_repo_and_reports_it(tmp_path):
    path = tmp_path / "variables.yaml"
    path.write_text("EXISTING:\n  repos: [other]\n")
    added = repo_admin._add_repo_to_config_map(path, {"EXISTING", "NEW"}, "gh-digest")
    assert sorted(added) == ["EXISTING", "NEW"]
    import yaml

    written = yaml.safe_load(path.read_text())
    assert written["EXISTING"]["repos"] == ["gh-digest", "other"]
    assert written["NEW"]["repos"] == ["gh-digest"]


def test_add_repo_to_config_map_no_write_when_repo_already_listed(tmp_path):
    path = tmp_path / "variables.yaml"
    path.write_text("N:\n  repos: [gh-digest]\n")
    before = path.read_text()
    assert repo_admin._add_repo_to_config_map(path, {"N"}, "gh-digest") == []
    assert path.read_text() == before


def test_prompt_missing_values_skips_present_and_writes_new(monkeypatch, tmp_path):
    enc = _PresentPath()
    monkeypatch.setattr(repo_admin.lib, "decrypt_variables", lambda: {"HAVE": "old"})
    written = {}
    monkeypatch.setattr(
        repo_admin.lib, "write_enc_file", lambda path, values: written.update(values)
    )
    got = repo_admin._prompt_missing_values(
        enc,
        {"HAVE", "NEED", "SKIP"},
        repo_admin.lib.decrypt_variables,
        lambda prompt: "typed" if "NEED" in prompt else "",
    )
    assert got == ["NEED"]
    assert written == {"HAVE": "old", "NEED": "typed"}


def test_bootstrap_secret_bindings_new_name_prompts_and_writes(monkeypatch):
    monkeypatch.setattr(repo_admin.lib, "SECRETS_ENC_FILE", _PresentPath())
    monkeypatch.setattr(repo_admin.lib, "load_secrets", dict)
    written = {}
    monkeypatch.setattr(
        repo_admin.lib, "write_enc_file", lambda path, values: written.update(values)
    )
    added = repo_admin._bootstrap_secret_bindings({"NEW"}, "gh-digest", lambda p: "tok")
    assert added == ["NEW"]
    assert written == {"NEW": [{"repos": ["gh-digest"], "value": "tok"}]}


def test_bootstrap_secret_bindings_existing_name_joins_first_binding(monkeypatch):
    monkeypatch.setattr(repo_admin.lib, "SECRETS_ENC_FILE", _PresentPath())
    monkeypatch.setattr(
        repo_admin.lib,
        "load_secrets",
        lambda: {"PAT": [{"repos": ["repo-a"], "value": "shared"}]},
    )
    written = {}
    monkeypatch.setattr(
        repo_admin.lib, "write_enc_file", lambda path, values: written.update(values)
    )

    def fail_prompt(_):
        raise AssertionError("must not prompt when the name already has a value")

    added = repo_admin._bootstrap_secret_bindings({"PAT"}, "gh-digest", fail_prompt)
    assert added == ["PAT"]
    assert written == {"PAT": [{"repos": ["gh-digest", "repo-a"], "value": "shared"}]}


def test_bootstrap_secret_bindings_no_write_when_repo_already_bound(monkeypatch):
    monkeypatch.setattr(repo_admin.lib, "SECRETS_ENC_FILE", _PresentPath())
    monkeypatch.setattr(
        repo_admin.lib,
        "load_secrets",
        lambda: {"PAT": [{"repos": ["gh-digest"], "value": "v"}]},
    )

    def fail_write(*a, **k):
        raise AssertionError("nothing changed; should not re-encrypt")

    monkeypatch.setattr(repo_admin.lib, "write_enc_file", fail_write)
    assert repo_admin._bootstrap_secret_bindings({"PAT"}, "gh-digest", input) == []


async def test_cmd_config_bootstrap_adds_repo_and_prints_next_steps(
    monkeypatch, capsys
):
    monkeypatch.setattr(
        repo_admin.lib,
        "fetch_workflow_texts",
        _async_return(["${{ secrets.PAT }} ${{ vars.HOST }}"]),
    )
    var_added = []
    monkeypatch.setattr(
        repo_admin,
        "_add_repo_to_config_map",
        lambda path, names, repo: var_added.append((set(names), repo)),
    )
    monkeypatch.setattr(repo_admin, "_prompt_missing_values", lambda *a, **k: [])
    sec_added = []
    monkeypatch.setattr(
        repo_admin,
        "_bootstrap_secret_bindings",
        lambda names, repo, prompt: sec_added.append((set(names), repo)),
    )
    assert (
        await repo_admin.cmd_config_bootstrap(argparse.Namespace(repo="gh-digest")) == 0
    )
    out = capsys.readouterr().out
    assert "secrets sync gh-digest --dry-run" in out
    assert "variables sync gh-digest --dry-run" in out
    assert sec_added == [({"PAT"}, "gh-digest")]
    assert var_added == [({"HOST"}, "gh-digest")]


async def test_cmd_config_bootstrap_errors_when_no_workflows(monkeypatch, capsys):
    monkeypatch.setattr(repo_admin.lib, "fetch_workflow_texts", _async_return([]))
    assert await repo_admin.cmd_config_bootstrap(argparse.Namespace(repo="r")) == 1
    assert "no .github/workflows/" in capsys.readouterr().err


def test_config_bootstrap_subcommand_is_registered_in_parser():
    args = repo_admin.build_parser().parse_args(["config", "bootstrap", "gh-digest"])
    assert args.func == repo_admin.cmd_config_bootstrap
    assert args.repo == "gh-digest"


# ---------------------------------------------------------------------------
# activity
# ---------------------------------------------------------------------------


def test_activity_subcommand_is_registered_in_parser():
    args = repo_admin.build_parser().parse_args(["activity"])
    assert args.func == repo_admin.activity.run
    assert args.window_months == 12
    assert args.half_life_days == 30
    assert args.limit == 20


def test_activity_subcommand_accepts_custom_knobs():
    args = repo_admin.build_parser().parse_args(
        ["activity", "--window-months", "3", "--half-life-days", "7", "--limit", "5"]
    )
    assert args.window_months == 3
    assert args.half_life_days == 7
    assert args.limit == 5


# ---------------------------------------------------------------------------
# features sync
# ---------------------------------------------------------------------------

FEATURES_ALL_OFF = {
    "has_issues": False,
    "has_wiki": False,
    "has_projects": False,
    "has_discussions": False,
}


def _features_worker(monkeypatch, current, desired, *, dry_run):
    calls = []

    async def fake_api_json(method, path, **kwargs):
        calls.append((method, kwargs.get("json")))
        return current

    monkeypatch.setattr(repo_admin, "api_json", fake_api_json)
    monkeypatch.setattr(repo_admin.lib, "repo_features", lambda name: desired)
    return repo_admin.make_features_worker("hugoh", dry_run), calls


async def test_features_worker_dry_run_reports_without_patching(monkeypatch):
    worker, calls = _features_worker(
        monkeypatch,
        {**FEATURES_ALL_OFF, "has_wiki": True},
        {"issues": True, "wiki": False},
        dry_run=True,
    )
    result = await worker(REPO)
    assert "would set: issues=True, wiki=False" in result.line
    assert result.status == Status.OK
    assert [m for m, _ in calls] == ["GET"]


async def test_features_worker_apply_patches_only_differing_fields(monkeypatch):
    worker, calls = _features_worker(
        monkeypatch,
        {**FEATURES_ALL_OFF, "has_wiki": True},
        {"issues": True, "wiki": False},
        dry_run=False,
    )
    await worker(REPO)
    assert ("PATCH", {"has_issues": True, "has_wiki": False}) in calls


async def test_features_worker_unchanged_when_at_target(monkeypatch):
    worker, calls = _features_worker(
        monkeypatch, {**FEATURES_ALL_OFF}, {"wiki": False}, dry_run=False
    )
    result = await worker(REPO)
    assert result.status == Status.UNCHANGED
    assert [m for m, _ in calls] == ["GET"]


def test_features_sync_subcommand_is_registered_in_parser():
    args = repo_admin.build_parser().parse_args(["features", "sync", "--dry-run"])
    assert args.func == repo_admin._features_sync
