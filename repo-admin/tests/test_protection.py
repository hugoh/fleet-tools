import base64

import protection
import pytest
from helpers import REPO, _FakeResponse, _FakeResponseWithJson
from lib import Status

# ---------------------------------------------------------------------------
# protection sync
# ---------------------------------------------------------------------------


def _check_runs_response(runs):
    return {"check_runs": runs}


def _run(name, conclusion, app_slug="github-actions", suite=1):
    return {
        "name": name,
        "conclusion": conclusion,
        "app": {"slug": app_slug},
        "check_suite": {"id": suite},
    }


def _patch_own_suites(monkeypatch, suite_ids):
    async def fake(owner, name, sha):
        return set(suite_ids)

    monkeypatch.setattr(protection, "_own_workflow_check_suite_ids", fake)


async def test_check_run_contexts_excludes_third_party_apps(monkeypatch):
    async def fake_api_json(*a, **k):
        return _check_runs_response(
            [
                _run("goci / goci", "success"),
                _run("DeepSource: Analysis", "success", app_slug="deepsource-io"),
            ]
        )

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    assert await protection._check_run_contexts("hugoh", "repo", ["sha"]) == [
        "goci / goci"
    ]


async def test_check_run_contexts_excludes_github_managed_setup_checks(monkeypatch):
    async def fake_api_json(method, path, **kwargs):
        if path.endswith("/check-runs"):
            return _check_runs_response(
                [
                    _run("lint", "success", suite=10),
                    _run("Analyze (python)", "success", suite=20),
                    _run("Analyze (actions)", "success", suite=20),
                    _run("github-advanced-security", "failure", suite=30),
                ]
            )
        if path.endswith("/actions/runs"):
            return {
                "workflow_runs": [
                    {"check_suite_id": 10, "path": ".github/workflows/hk.yml"},
                    {
                        "check_suite_id": 20,
                        "path": "dynamic/github-code-scanning/codeql",
                    },
                    {
                        "check_suite_id": 30,
                        "path": "dynamic/agents/github-advanced-security",
                    },
                ]
            }
        raise AssertionError(path)

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    assert await protection._check_run_contexts("hugoh", "repo", ["sha"]) == ["lint"]


async def test_own_workflow_check_suite_ids_keeps_only_repo_workflow_paths(monkeypatch):
    async def fake_api_json(method, path, **kwargs):
        return {
            "workflow_runs": [
                {"check_suite_id": 10, "path": ".github/workflows/hk.yml"},
                {"check_suite_id": 20, "path": "dynamic/github-code-scanning/codeql"},
            ]
        }

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    assert await protection._own_workflow_check_suite_ids("hugoh", "repo", "sha") == {
        10
    }


async def test_check_run_contexts_replaces_skip_artifact_with_composite_alias(
    monkeypatch,
):
    responses = {
        "sha1": _check_runs_response(
            [_run("hk / hk", "failure"), _run("release", "skipped")]
        ),
        "sha2": _check_runs_response(
            [_run("hk / hk", "success"), _run("release / release", "success")]
        ),
    }

    async def fake_api_json(method, path, **kwargs):
        sha = path.rsplit("/", 2)[1]
        return responses[sha]

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    contexts = await protection._check_run_contexts("hugoh", "repo", ["sha1", "sha2"])
    assert contexts == ["hk / hk", "release / release"]


async def test_check_run_contexts_keeps_legitimately_skipped_check(monkeypatch):
    responses = {
        "sha1": _check_runs_response(
            [_run("hk / hk", "success"), _run("pages", "skipped")]
        ),
    }

    async def fake_api_json(method, path, **k):
        return responses["sha1"]

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    contexts = await protection._check_run_contexts("hugoh", "repo", ["sha1"])
    assert contexts == ["hk / hk", "pages"]


async def test_check_run_contexts_collapses_matrix_legs_when_gate_present(monkeypatch):
    async def fake_api_json(method, path, **k):
        return _check_runs_response(
            [
                _run("hk / hk", "success"),
                _run("jj / gate", "success"),
                _run("jj / versions", "success"),
                _run("jj / test (0.42)", "success"),
                _run("jj / test (0.43)", "success"),
            ]
        )

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    contexts = await protection._check_run_contexts("hugoh", "repo", ["sha1"])
    assert contexts == ["hk / hk", "jj / gate", "jj / versions"]


async def test_check_run_contexts_skips_head_with_in_progress_runs(monkeypatch):
    by_sha = {
        "busy": [_run("anodizer (ubuntu-latest)", None), _run("test", "success")],
        "done": [_run("cross-gate", "success"), _run("test", "success")],
    }

    async def fake_api_json(method, path, **k):
        return _check_runs_response(by_sha[path.split("/commits/")[1].split("/")[0]])

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    contexts = await protection._check_run_contexts("hugoh", "repo", ["busy", "done"])
    assert contexts == ["cross-gate", "test"]


async def test_check_run_contexts_drops_jobs_covered_by_a_needs_gate(monkeypatch):
    async def fake_api_json(method, path, **k):
        return _check_runs_response(
            [
                _run("cross-gate", "success"),
                _run("changes", "success"),
                _run("anodizer (ubuntu-latest)", "success"),
                _run("anodizer (macos-latest)", "success"),
                _run("test", "success"),
            ]
        )

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    contexts = await protection._check_run_contexts(
        "hugoh", "repo", ["sha"], gate_covered_jobs={"changes", "anodizer"}
    )
    assert contexts == ["cross-gate", "test"]


async def test_check_run_contexts_keeps_covered_jobs_when_gate_not_sampled(monkeypatch):
    async def fake_api_json(method, path, **k):
        return _check_runs_response([_run("changes", "success")])

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    contexts = await protection._check_run_contexts(
        "hugoh", "repo", ["sha"], gate_covered_jobs={"changes"}
    )
    assert contexts == ["changes"]


async def test_gate_covered_jobs_reads_needs_and_strips_matrix_suffix(monkeypatch):
    async def fake_docs(owner, name, ref):
        return [
            {
                "jobs": {
                    "changes": {},
                    "anodizer": {"name": "anodizer (${{ matrix.os }})"},
                    "cross-gate": {"needs": ["changes", "anodizer"]},
                    "test": {},
                }
            }
        ]

    monkeypatch.setattr(protection, "_workflow_docs", fake_docs)
    assert await protection._gate_covered_jobs("o", "r", "main") == {
        "changes",
        "anodizer",
    }


async def test_check_run_contexts_drops_push_only_jobs(monkeypatch):
    async def fake_api_json(method, path, **k):
        return _check_runs_response(
            [
                _run("test", "success"),
                _run("tag", "skipped"),
                _run("build (${{ matrix.os }})", "skipped"),
                _run("release", "skipped"),
            ]
        )

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    contexts = await protection._check_run_contexts(
        "hugoh", "repo", ["sha"], push_only_jobs={"tag", "build", "release"}
    )
    assert contexts == ["test"]


async def test_push_only_jobs_follows_event_if_and_needs(monkeypatch):
    async def fake_docs(owner, name, ref):
        return [
            {
                "jobs": {
                    "test": {},
                    "tag": {
                        "if": "github.event_name == 'push' && github.ref == 'refs/heads/main'"
                    },
                    "build": {"name": "build (${{ matrix.os }})", "needs": "tag"},
                    "release": {"needs": ["tag", "build"]},
                    "mixed": {"if": "github.event_name == 'pull_request' || push"},
                    "filtered": {
                        "if": "needs.changes.outputs.links == 'true' || github.event_name == 'workflow_dispatch'"
                    },
                    "filtered-gate": {"needs": ["filtered"]},
                }
            }
        ]

    monkeypatch.setattr(protection, "_workflow_docs", fake_docs)
    assert await protection._push_only_jobs("o", "r", "main") == {
        "tag",
        "build",
        "release",
    }


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("github.event_name == 'push'", True),
        ("${{ github.event_name == 'push' }}", True),
        ("event_name == 'schedule' || github.event_name == 'workflow_dispatch'", True),
        ("github.event_name == 'push' && needs.a.result == 'success'", True),
        ("github.event_name == 'push' || x", False),
        ("needs.a.outputs.b == 'true' || github.event_name == 'push'", False),
        ("github.event_name == 'pull_request' || github.event_name == 'push'", False),
        ("(github.event_name == 'push')", False),
        ("always()", False),
    ],
)
def test_never_runs_on_pull_request(condition, expected):
    assert protection._never_runs_on_pull_request(condition) is expected


async def test_push_only_jobs_keeps_job_conditioned_on_needs_outputs(monkeypatch):
    async def fake_docs(owner, name, ref):
        return [
            {
                "jobs": {
                    "lychee": {
                        "needs": ["changes"],
                        "if": "needs.changes.outputs.links == 'true' || github.event_name == 'workflow_dispatch'",
                    }
                }
            }
        ]

    monkeypatch.setattr(protection, "_workflow_docs", fake_docs)
    assert await protection._push_only_jobs("o", "r", "main") == set()


async def test_path_filtered_gate_workflow_requires_only_the_gate(monkeypatch):
    async def fake_docs(owner, name, ref):
        return [
            {
                "jobs": {
                    "changes": {},
                    "lychee": {
                        "needs": ["changes"],
                        "if": "needs.changes.outputs.links == 'true' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
                    },
                    "lychee-gate": {"if": "always()", "needs": ["changes", "lychee"]},
                }
            }
        ]

    async def fake_api_json(method, path, **k):
        return _check_runs_response(
            [
                _run("lychee-gate", "success"),
                _run("lychee", "skipped"),
                _run("changes", "success"),
                _run("hk / lint", "success"),
            ]
        )

    monkeypatch.setattr(protection, "_workflow_docs", fake_docs)
    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    contexts = await protection._check_run_contexts(
        "hugoh",
        "repo",
        ["sha"],
        gate_covered_jobs=await protection._gate_covered_jobs("o", "r", "main"),
        push_only_jobs=await protection._push_only_jobs("o", "r", "main"),
    )
    assert contexts == ["hk / lint", "lychee-gate"]


async def test_check_run_contexts_keeps_matrix_legs_without_gate(monkeypatch):
    async def fake_api_json(method, path, **k):
        return _check_runs_response(
            [
                _run("test (0.42)", "success"),
                _run("test (0.43)", "success"),
            ]
        )

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    contexts = await protection._check_run_contexts("hugoh", "repo", ["sha1"])
    assert contexts == ["test (0.42)", "test (0.43)"]


async def test_check_run_contexts_collapses_local_matrix_with_named_gate(monkeypatch):
    async def fake_api_json(method, path, **k):
        return _check_runs_response(
            [
                _run("git-gate", "success"),
                _run("git (ubuntu-24.04)", "success"),
                _run("git (ubuntu-22.04)", "success"),
            ]
        )

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    contexts = await protection._check_run_contexts("hugoh", "repo", ["sha1"])
    assert contexts == ["git-gate"]


async def test_check_run_contexts_drops_conditional_reusable_checks_shadowed_by_wrapper_gate(
    monkeypatch,
):
    async def fake_api_json(method, path, **k):
        return _check_runs_response(
            [
                _run("jj-gate", "success"),
                _run("jj / gate", "success"),
                _run("jj / versions", "success"),
                _run("hk / hk", "success"),
            ]
        )

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    _patch_own_suites(monkeypatch, [1])
    contexts = await protection._check_run_contexts("hugoh", "repo", ["sha1"])
    assert contexts == ["hk / hk", "jj-gate"]


def test_drop_shadowed_by_wrapper_gate_drops_bare_skipped_caller_job():
    assert protection._drop_shadowed_by_wrapper_gate(
        {"git", "git-gate", "git / gate", "jj-gate", "hk / hk"}
    ) == {"git-gate", "jj-gate", "hk / hk"}


def test_collapse_matrix_legs_drops_prefixed_legs_covered_by_gate():
    assert protection._collapse_matrix_legs(
        {"jj / gate", "jj / test (0.42)", "jj / test (0.43)"}
    ) == {"jj / gate"}


def test_collapse_matrix_legs_handles_nested_reusable_workflow_prefix():
    assert protection._collapse_matrix_legs(
        {"compat / jj / gate", "compat / jj / test (0.42)"}
    ) == {"compat / jj / gate"}


def test_collapse_matrix_legs_matches_unprefixed_job_named_gate():
    assert protection._collapse_matrix_legs(
        {"git-gate", "git (ubuntu-24.04)", "git (ubuntu-22.04)"}
    ) == {"git-gate"}


def test_collapse_matrix_legs_keeps_legs_without_a_gate():
    legs = {"test (0.42)", "test (0.43)"}
    assert protection._collapse_matrix_legs(set(legs)) == legs


def test_collapse_matrix_legs_keeps_the_generator_and_plain_checks():
    assert protection._collapse_matrix_legs(
        {"jj / gate", "jj / versions", "jj / test (0.42)", "hk / hk"}
    ) == {"jj / gate", "jj / versions", "hk / hk"}


def test_collapse_matrix_legs_matches_gate_only_within_the_same_prefix():
    contexts = {"gate", "jj / test (0.42)"}
    assert protection._collapse_matrix_legs(set(contexts)) == contexts


def _protection_state(*, contexts=("build", "test"), **overrides):
    state = {
        "required_status_checks": {"contexts": list(contexts), "strict": True},
        "enforce_admins": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "required_pull_request_reviews": {"required_approving_review_count": 0},
    }
    state.update(overrides)
    return state


def test_branch_protection_up_to_date_matches_baseline():
    current = _protection_state(contexts=["build", "test"])
    assert protection.branch_protection_up_to_date(current, ["test", "build"]) is True


def test_branch_protection_up_to_date_false_when_contexts_differ():
    current = _protection_state(contexts=["build"])
    assert protection.branch_protection_up_to_date(current, ["test", "build"]) is False


def test_branch_protection_up_to_date_false_when_unprotected():
    assert protection.branch_protection_up_to_date(None, ["build"]) is False


def test_branch_protection_payload():
    payload = protection.branch_protection_payload(["build", "test"])
    assert payload == {
        "required_status_checks": {"strict": True, "contexts": ["build", "test"]},
        "enforce_admins": True,
        "required_pull_request_reviews": {"required_approving_review_count": 0},
        "restrictions": None,
        "allow_force_pushes": False,
        "allow_deletions": False,
    }


def test_branch_protection_payload_no_contexts_omits_required_status_checks():
    payload = protection.branch_protection_payload([])
    assert payload["required_status_checks"] is None
    assert payload["enforce_admins"] is True
    assert payload["allow_force_pushes"] is False
    assert payload["allow_deletions"] is False


def test_branch_protection_up_to_date_true_with_no_contexts_and_none_required():
    current = _protection_state(required_status_checks=None)
    assert protection.branch_protection_up_to_date(current, []) is True


def _branch_protection_worker(
    monkeypatch,
    *,
    dry_run,
    shas=(),
    contexts=(),
    current=None,
    status_code=200,
    track_calls=False,
    clear_stale_checks=False,
    repo_rulesets=(),
    org_rulesets=(),
    base_checks=(),
    adopt_renamed_checks=False,
):
    async def fake_shas(owner, name):
        return list(shas)

    async def fake_base_checks(owner, name, default_branch):
        return set(base_checks)

    async def fake_contexts(
        owner,
        name,
        shas,
        own_reusable_job_prefixes=None,
        gate_covered_jobs=None,
        push_only_jobs=None,
    ):
        return list(contexts)

    if current is not None:

        class _ProtectionResponse(_FakeResponse):
            def json(self):
                return current

        response = _ProtectionResponse(status_code)
    else:
        response = _FakeResponse(status_code)

    calls = [] if track_calls else None

    async def fake_api_raw(method, *a, **k):
        if calls is not None:
            calls.append(method)
        return response

    async def fake_prefixes(owner, name, ref):
        return set()

    async def fake_rulesets(owner, name, default_branch):
        return list(repo_rulesets), list(org_rulesets)

    monkeypatch.setattr(protection, "_recent_pr_head_shas", fake_shas)
    monkeypatch.setattr(protection, "_check_run_contexts", fake_contexts)
    monkeypatch.setattr(protection, "_own_reusable_job_prefixes", fake_prefixes)
    monkeypatch.setattr(protection, "_gate_covered_jobs", fake_prefixes)
    monkeypatch.setattr(protection, "_push_only_jobs", fake_prefixes)
    monkeypatch.setattr(protection, "_matching_rulesets", fake_rulesets)
    monkeypatch.setattr(protection, "_base_branch_check_names", fake_base_checks)
    monkeypatch.setattr(protection, "api_raw", fake_api_raw)
    worker = protection.make_branch_protection_worker(
        owner="hugoh",
        dry_run=dry_run,
        clear_stale_checks=clear_stale_checks,
        adopt_renamed_checks=adopt_renamed_checks,
    )
    return (worker, calls) if track_calls else worker


async def test_branch_protection_worker_dry_run_ok_when_no_prs(monkeypatch):
    worker = _branch_protection_worker(monkeypatch, dry_run=True, status_code=404)
    result = await worker(REPO)
    assert result.status == Status.OK
    assert "no pull requests found yet" in result.line
    assert "(none yet)" in result.line


async def test_branch_protection_worker_dry_run_ok_when_no_check_runs(monkeypatch):
    worker = _branch_protection_worker(
        monkeypatch, dry_run=True, shas=["sha"], status_code=404
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert "no check runs found" in result.line
    assert "(none yet)" in result.line


async def test_branch_protection_worker_apply_ok_when_no_prs_yet(monkeypatch):
    async def fake_shas(owner, name):
        return []

    calls = []

    async def fake_api_raw(method, *a, **k):
        calls.append(method)
        return _FakeResponse(404) if method == "GET" else _FakeResponse(200)

    monkeypatch.setattr(protection, "_recent_pr_head_shas", fake_shas)
    monkeypatch.setattr(protection, "api_raw", fake_api_raw)
    worker = protection.make_branch_protection_worker(owner="hugoh", dry_run=False)
    result = await worker(REPO)
    assert result.status == Status.OK
    assert result.tag == protection.Tag.APPLIED_NO_CHECKS
    assert "protected" in result.line
    assert "PUT" in calls


async def test_branch_protection_worker_dry_run_limited_unchanged_when_plan_gated(
    monkeypatch,
):
    worker = _branch_protection_worker(
        monkeypatch, dry_run=True, shas=["sha"], contexts=[], status_code=403
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    assert result.line == (
        f"{'repo':<30} unchanged: private repo, plan does not allow branch protection"
    )


async def test_branch_protection_worker_apply_limited_unchanged_when_plan_gated(
    monkeypatch,
):
    worker = _branch_protection_worker(
        monkeypatch, dry_run=False, shas=["sha"], contexts=[], status_code=403
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    assert result.line == (
        f"{'repo':<30} unchanged: private repo, plan does not allow branch protection"
    )


async def test_branch_protection_worker_dry_run_unchanged_line(monkeypatch):
    worker = _branch_protection_worker(
        monkeypatch,
        dry_run=True,
        shas=["sha"],
        contexts=["build", "test"],
        current=_protection_state(contexts=["build", "test"]),
    )
    result = await worker(REPO)
    assert result.status == Status.UNCHANGED
    assert result.line == f"{'repo':<30} unchanged: build, test"


async def test_branch_protection_worker_dry_run_shows_old_contexts(monkeypatch):
    worker = _branch_protection_worker(
        monkeypatch,
        dry_run=True,
        shas=["sha"],
        contexts=["build", "test"],
        current=_protection_state(contexts=["build"]),
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert result.line == (
        f"{'repo':<30} would update -> require: build, test (was: build)"
    )


async def test_branch_protection_worker_keeps_checks_when_sampling_yields_none(
    monkeypatch,
):
    worker = _branch_protection_worker(
        monkeypatch,
        dry_run=True,
        shas=["eba79c"],
        contexts=[],
        current=_protection_state(contexts=["check", "lychee"]),
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    assert "keeping check, lychee" in result.line
    assert "would update" not in result.line


async def test_branch_protection_worker_apply_keeps_stale_checks_without_put(
    monkeypatch,
):
    worker, calls = _branch_protection_worker(
        monkeypatch,
        dry_run=False,
        shas=["eba79c"],
        contexts=[],
        current=_protection_state(contexts=["check", "lychee"]),
        track_calls=True,
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    assert result.tag == protection.Tag.APPLIED
    assert "PUT" not in calls


async def test_branch_protection_worker_clears_stale_checks_when_opted_in(monkeypatch):
    worker = _branch_protection_worker(
        monkeypatch,
        dry_run=True,
        shas=["eba79c"],
        contexts=[],
        current=_protection_state(contexts=["check", "lychee"]),
        clear_stale_checks=True,
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert "would update -> require: (none yet) (was: check, lychee)" in result.line


def test_reconcile_reusable_prefix_keeps_existing_spelling():
    assert protection._reconcile_reusable_prefix(["lint"], ["hk / lint"]) == [
        "hk / lint"
    ]
    assert protection._reconcile_reusable_prefix(["hk / lint"], ["lint"]) == ["lint"]


def test_reconcile_reusable_prefix_does_not_touch_unrelated_contexts():
    assert protection._reconcile_reusable_prefix(["hk / lint", "e2e"], ["check"]) == [
        "e2e",
        "hk / lint",
    ]
    assert protection._reconcile_reusable_prefix([], ["hk / lint"]) == []


def test_reconcile_reusable_prefix_does_not_guess_on_ambiguous_match():
    # Two existing checks both end in " / test" -- picking either would
    # silently and arbitrarily bind "test" to the wrong required check.
    # Treat it as unmatched and keep the sampled spelling.
    assert protection._reconcile_reusable_prefix(
        ["test"], ["backend / test", "frontend / test"]
    ) == ["test"]


def test_reconcile_reusable_prefix_does_not_guess_on_ambiguous_match_reverse():
    # "ci / build / test" ambiguously matches both "build / test" and "test"
    # as prefix-stripped existing forms -- same ambiguity, other direction.
    assert protection._reconcile_reusable_prefix(
        ["ci / build / test"], ["build / test", "test"]
    ) == ["ci / build / test"]


def test_reconcile_reusable_prefix_honours_sample_when_base_branch_renamed():
    # `main` runs report bare `Tests`; the required gate still names the old
    # `test / Tests`. That's a rename, not per-run flakiness -- take the sample.
    assert protection._reconcile_reusable_prefix(
        ["Tests"], ["test / Tests"], base_branch_checks={"Tests"}
    ) == ["Tests"]


def test_reconcile_reusable_prefix_keeps_existing_when_base_branch_confirms_it():
    # `main` still reports the prefixed `hk / lint`, so the bare `lint` on the
    # PR is the known cross-run inconsistency -- keep the existing spelling.
    assert protection._reconcile_reusable_prefix(
        ["lint"], ["hk / lint"], base_branch_checks={"hk / lint"}
    ) == ["hk / lint"]


def test_reconcile_reusable_prefix_keeps_existing_when_base_branch_inconclusive():
    assert protection._reconcile_reusable_prefix(
        ["lint"], ["hk / lint"], base_branch_checks=set()
    ) == ["hk / lint"]


async def test_base_branch_check_names_collects_github_actions_run_names(monkeypatch):
    async def fake_api_json(method, path, **kwargs):
        assert kwargs["params"]["sha"] == "main"
        return [{"sha": "c1"}, {"sha": "c2"}]

    async def fake_runs(owner, name, sha):
        return {
            "c1": [_run("Tests", "success")],
            "c2": [_run("check / lint", "success")],
        }[sha]

    monkeypatch.setattr(protection, "api_json", fake_api_json)
    monkeypatch.setattr(protection, "_github_actions_check_runs", fake_runs)
    assert await protection._base_branch_check_names("hugoh", "repo", "main") == {
        "Tests",
        "check / lint",
    }


def test_reconcile_reusable_prefix_prefer_sampled_overrides_heuristic():
    assert protection._reconcile_reusable_prefix(
        ["Tests"], ["test / Tests"], prefer_sampled=True
    ) == ["Tests"]


async def test_branch_protection_worker_adopts_renamed_gate_confirmed_by_base_branch(
    monkeypatch,
):
    worker, calls = _branch_protection_worker(
        monkeypatch,
        dry_run=False,
        shas=["prsha"],
        contexts=["Tests"],
        current=_protection_state(contexts=["test / Tests"]),
        base_checks=["Tests"],
        track_calls=True,
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert "protected (Tests)" in result.line
    assert "PUT" in calls


async def test_branch_protection_worker_adopt_renamed_checks_flag_breaks_deadlock(
    monkeypatch,
):
    # The rename lives only on the open PR; `main` still reports `test / Tests`,
    # so the base-branch check can't confirm it. --adopt-renamed-checks trusts
    # the PR sample and swaps the gate anyway.
    worker, calls = _branch_protection_worker(
        monkeypatch,
        dry_run=False,
        shas=["prsha"],
        contexts=["Tests"],
        current=_protection_state(contexts=["test / Tests"]),
        base_checks=["test / Tests"],
        adopt_renamed_checks=True,
        track_calls=True,
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert "protected (Tests)" in result.line
    assert "PUT" in calls


async def test_branch_protection_worker_adopt_renamed_checks_keeps_live_push_only_checks(
    monkeypatch,
):
    # `pages` never runs on a PR so the sample lacks it, but `main` still
    # reports it: adopting a rename must not drop a gate that is still live.
    worker = _branch_protection_worker(
        monkeypatch,
        dry_run=True,
        shas=["prsha"],
        contexts=["Tests"],
        current=_protection_state(contexts=["test / Tests", "pages"]),
        base_checks=["test / Tests", "pages"],
        adopt_renamed_checks=True,
    )
    result = await worker(REPO)
    assert "require: Tests, pages" in result.line
    assert "dropped test / Tests" in result.line


async def test_branch_protection_worker_adopt_renamed_checks_drops_dead_unmatched_check(
    monkeypatch,
):
    worker = _branch_protection_worker(
        monkeypatch,
        dry_run=True,
        shas=["prsha"],
        contexts=["Tests"],
        current=_protection_state(contexts=["test / Tests", "retired"]),
        base_checks=["test / Tests"],
        adopt_renamed_checks=True,
    )
    result = await worker(REPO)
    assert "require: Tests " in result.line or "require: Tests (" in result.line
    assert "retired" in result.line


async def test_branch_protection_worker_without_flag_keeps_stale_gate_on_deadlock(
    monkeypatch,
):
    worker, calls = _branch_protection_worker(
        monkeypatch,
        dry_run=True,
        shas=["prsha"],
        contexts=["Tests"],
        current=_protection_state(contexts=["test / Tests"]),
        base_checks=["test / Tests"],
        track_calls=True,
    )
    result = await worker(REPO)
    assert "PUT" not in calls
    assert "kept test / Tests over sampled Tests" in result.line
    assert result.tag == protection.Tag.RENAME_CANDIDATE


async def test_branch_protection_worker_keeps_existing_check_name_on_prefix_flip(
    monkeypatch,
):
    # main reports `hk / lint` (a reusable-workflow check); the latest PR's run
    # happened to report bare `lint` -- a GitHub cross-run naming inconsistency.
    # The gate must stay on `hk / lint` or it strands pending forever.
    worker, calls = _branch_protection_worker(
        monkeypatch,
        dry_run=True,
        shas=["eba79c"],
        contexts=["lint"],
        current=_protection_state(contexts=["hk / lint"]),
        track_calls=True,
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    assert "PUT" not in calls
    assert "kept hk / lint over sampled lint" in result.line


async def test_branch_protection_worker_apply_unchanged_when_already_protected(
    monkeypatch,
):
    worker, calls = _branch_protection_worker(
        monkeypatch,
        dry_run=False,
        shas=["sha"],
        contexts=["build", "test"],
        current=_protection_state(contexts=["build", "test"]),
        track_calls=True,
    )
    result = await worker(REPO)
    assert result.status == Status.UNCHANGED
    assert result.line == f"{'repo':<30} unchanged: build, test"
    assert result.tag == protection.Tag.APPLIED
    assert "PUT" not in calls


async def test_branch_protection_worker_apply_ok_when_updating_from_stale_state(
    monkeypatch,
):
    worker = _branch_protection_worker(
        monkeypatch,
        dry_run=False,
        shas=["sha"],
        contexts=["build", "test"],
        current=_protection_state(contexts=["build"]),
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert result.line == f"{'repo':<30} protected (build, test)"
    assert result.tag == protection.Tag.APPLIED


# ---------------------------------------------------------------------------
# protection sync -- unprotecting excluded repos
#
# A repo added to branch-protection-exclude.yaml after already being
# protected (e.g. before the config existed) must have that protection
# actively removed -- excluding a repo from the "apply" list alone leaves
# whatever protection it already has in place forever, since nothing else
# ever calls the API to remove it.
# ---------------------------------------------------------------------------


def _branch_unprotect_worker(monkeypatch, *, dry_run, status_code, track_calls=False):
    response = _FakeResponse(status_code)
    calls = [] if track_calls else None

    async def fake_api_raw(method, *a, **k):
        if calls is not None:
            calls.append(method)
        return response

    monkeypatch.setattr(protection, "api_raw", fake_api_raw)
    worker = protection.make_branch_unprotect_worker(owner="hugoh", dry_run=dry_run)
    return (worker, calls) if track_calls else worker


async def test_branch_unprotect_worker_removes_existing_protection(monkeypatch):
    worker, calls = _branch_unprotect_worker(
        monkeypatch, dry_run=False, status_code=200, track_calls=True
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert result.tag == protection.Tag.UNPROTECTED
    assert "removed branch protection" in result.line
    assert calls == ["GET", "DELETE"]


async def test_branch_unprotect_worker_dry_run_does_not_delete(monkeypatch):
    worker, calls = _branch_unprotect_worker(
        monkeypatch, dry_run=True, status_code=200, track_calls=True
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert "would remove branch protection" in result.line
    assert calls == ["GET"]


async def test_branch_unprotect_worker_already_unprotected_is_unchanged(monkeypatch):
    worker, calls = _branch_unprotect_worker(
        monkeypatch, dry_run=False, status_code=404, track_calls=True
    )
    result = await worker(REPO)
    assert result.status == Status.UNCHANGED
    assert result.tag is None
    assert calls == ["GET"]


# ---------------------------------------------------------------------------
# protection sync -- reusable-workflow recognition (signal 2)
# ---------------------------------------------------------------------------


def _patch_hk_lint_check_run(monkeypatch):
    async def fake_api_json(method, path, **kwargs):
        if path.endswith("/check-runs"):
            return _check_runs_response([_run("hk / lint", "success", suite=999)])
        if path.endswith("/actions/runs"):
            return {
                "workflow_runs": [
                    {
                        "check_suite_id": 999,
                        "path": "hugoh/gh-workflows/.github/workflows/hk.yml@abc",
                    }
                ]
            }
        raise AssertionError(path)

    monkeypatch.setattr(protection, "api_json", fake_api_json)


async def test_check_run_contexts_keeps_reusable_workflow_check_by_job_prefix(
    monkeypatch,
):
    _patch_hk_lint_check_run(monkeypatch)
    contexts = await protection._check_run_contexts("hugoh", "repo", ["sha"], {"hk"})
    assert contexts == ["hk / lint"]


async def test_check_run_contexts_drops_reusable_check_without_prefix(monkeypatch):
    """The exact C2 symptom: a `hk / lint` check whose check-suite maps to an
    external child workflow run is dropped when the job prefix isn't known.
    """
    _patch_hk_lint_check_run(monkeypatch)
    assert await protection._check_run_contexts("hugoh", "repo", ["sha"]) == []


def test_own_reusable_check_matches_first_segment_and_matrix_leg():
    assert protection._own_reusable_check("hk / lint", {"hk"}) is True
    assert protection._own_reusable_check("hk / lint (3.12)", {"hk"}) is True
    assert protection._own_reusable_check("a / b / c", {"a"}) is True
    assert protection._own_reusable_check("hk", {"hk"}) is False
    assert protection._own_reusable_check("Analyze (go)", {"hk"}) is False
    assert protection._own_reusable_check("CodeQL", {"hk"}) is False


async def test_own_reusable_job_prefixes_reads_uses_jobs(monkeypatch):
    hk_yml = base64.b64encode(
        b"jobs:\n  hk:\n    uses: hugoh/gh-workflows/.github/workflows/hk.yml@x\n"
    ).decode()
    ci_yml = base64.b64encode(
        b"jobs:\n  build:\n    name: Build\n    runs-on: ubuntu-latest\n    steps: []\n"
    ).decode()

    async def fake_api_raw(method, path, **kwargs):
        assert path.endswith("/contents/.github/workflows")
        return _FakeResponseWithJson(
            200,
            [
                {"name": "hk.yml", "type": "file"},
                {"name": "ci.yml", "type": "file"},
                {"name": "README.md", "type": "file"},
            ],
        )

    async def fake_api_json(method, path, **kwargs):
        content = hk_yml if path.endswith("hk.yml") else ci_yml
        return {"content": content}

    monkeypatch.setattr(protection, "api_raw", fake_api_raw)
    monkeypatch.setattr(protection, "api_json", fake_api_json)
    prefixes = await protection._own_reusable_job_prefixes("hugoh", "repo", "main")
    assert prefixes == {"hk"}


async def test_own_reusable_job_prefixes_empty_when_no_workflows_dir(monkeypatch):
    async def fake_api_raw(method, path, **kwargs):
        return _FakeResponse(404)

    monkeypatch.setattr(protection, "api_raw", fake_api_raw)
    assert await protection._own_reusable_job_prefixes("hugoh", "r", "main") == set()


# ---------------------------------------------------------------------------
# protection sync -- ChecksTarget / ruleset helpers
# ---------------------------------------------------------------------------


def _checks_rule(contexts, *, strict=True, integration=None):
    return {
        "type": "required_status_checks",
        "parameters": {
            "strict_required_status_checks_policy": strict,
            "required_status_checks": [
                {
                    "context": c,
                    **({"integration_id": integration} if integration else {}),
                }
                for c in contexts
            ],
        },
    }


def _ruleset(contexts=("hk / lint",), *, rid=1, enforcement="active", **over):
    rs = {
        "id": rid,
        "name": "main-protection",
        "target": "branch",
        "enforcement": enforcement,
        "source_type": "Repository",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [
            {"type": "pull_request"},
            _checks_rule(contexts),
            {"type": "deletion"},
        ],
        "bypass_actors": [
            {"actor_id": 5, "actor_type": "Integration", "bypass_mode": "pull_request"}
        ],
    }
    rs.update(over)
    return rs


def test_checks_target_current_contexts_union():
    classic = {"required_status_checks": {"contexts": ["a"], "strict": True}}
    target = protection.ChecksTarget(
        classic=classic, repo_rulesets=[_ruleset(["b", "c"])]
    )
    assert target.mechanism == "both"
    assert target.current_contexts() == ["a", "b", "c"]


def test_checks_target_mechanism_ruleset_only():
    target = protection.ChecksTarget(classic=None, repo_rulesets=[_ruleset()])
    assert target.mechanism == "ruleset"
    assert target.current_contexts() == ["hk / lint"]


def test_ruleset_ref_matches():
    m = protection._ruleset_ref_matches
    assert m({"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}}, "main")
    assert m({"ref_name": {"include": ["~ALL"]}}, "trunk")
    assert m({"ref_name": {"include": ["refs/heads/main"]}}, "main")
    assert not m({"ref_name": {"include": ["refs/heads/release/*"]}}, "main")
    assert not m(
        {"ref_name": {"include": ["~ALL"], "exclude": ["refs/heads/main"]}}, "main"
    )


def test_ruleset_checks_payload_round_trips_everything_else():
    ruleset = _ruleset(["check"], integration=None)
    payload = protection.ruleset_checks_payload(ruleset, ["hk / lint"])
    assert set(payload) == {
        "name",
        "target",
        "enforcement",
        "conditions",
        "rules",
        "bypass_actors",
    }
    assert payload["bypass_actors"] == ruleset["bypass_actors"]
    assert payload["conditions"] == ruleset["conditions"]
    rule_types = [r["type"] for r in payload["rules"]]
    assert rule_types == ["pull_request", "required_status_checks", "deletion"]
    checks_rule = payload["rules"][1]["parameters"]
    assert checks_rule["required_status_checks"] == [
        {"context": "hk / lint", "integration_id": protection.GITHUB_ACTIONS_APP_ID}
    ]
    assert checks_rule["strict_required_status_checks_policy"] is True


def test_ruleset_checks_payload_preserves_null_integration_when_set_unchanged():
    ruleset = _ruleset(["hk / lint"], integration=None)
    payload = protection.ruleset_checks_payload(ruleset, ["hk / lint"])
    assert payload["rules"][1]["parameters"]["required_status_checks"] == [
        {"context": "hk / lint"}
    ]


def test_checks_target_up_to_date_ruleset():
    target = protection.ChecksTarget(
        classic=None, repo_rulesets=[_ruleset(["hk / lint"])]
    )
    assert protection.checks_target_up_to_date(target, ["hk / lint"]) is True
    assert protection.checks_target_up_to_date(target, ["check"]) is False


# ---------------------------------------------------------------------------
# protection sync -- ruleset worker
# ---------------------------------------------------------------------------


def _patch_branch_protection_lookups(monkeypatch, *, contexts, matching_rulesets=()):
    async def fake_shas(owner, name):
        return ["sha"]

    async def fake_contexts(
        owner,
        name,
        shas,
        own_reusable_job_prefixes=None,
        gate_covered_jobs=None,
        push_only_jobs=None,
    ):
        return list(contexts)

    async def fake_prefixes(owner, name, ref):
        return {"hk"}

    async def fake_rulesets(owner, name, default_branch):
        return list(matching_rulesets), []

    monkeypatch.setattr(protection, "_recent_pr_head_shas", fake_shas)
    monkeypatch.setattr(protection, "_check_run_contexts", fake_contexts)
    monkeypatch.setattr(protection, "_own_reusable_job_prefixes", fake_prefixes)
    monkeypatch.setattr(protection, "_gate_covered_jobs", fake_prefixes)
    monkeypatch.setattr(protection, "_push_only_jobs", fake_prefixes)
    monkeypatch.setattr(protection, "_matching_rulesets", fake_rulesets)


def _ruleset_worker(monkeypatch, *, dry_run, contexts, repo_rulesets, classic_code=404):
    calls = []
    _patch_branch_protection_lookups(
        monkeypatch, contexts=contexts, matching_rulesets=repo_rulesets
    )

    async def fake_api_raw(method, path, **kwargs):
        calls.append((method, path, kwargs.get("json")))
        if path.endswith("/protection"):
            return _FakeResponse(classic_code)
        return _FakeResponse(200)

    monkeypatch.setattr(protection, "api_raw", fake_api_raw)
    worker = protection.make_branch_protection_worker(owner="hugoh", dry_run=dry_run)
    return worker, calls


async def test_ruleset_worker_dry_run_reports_would_update_without_put(monkeypatch):
    worker, calls = _ruleset_worker(
        monkeypatch,
        dry_run=True,
        contexts=["hk / lint"],
        repo_rulesets=[_ruleset(["check"])],
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert "would update ruleset -> require: hk / lint (was: check)" in result.line
    assert not any(m == "PUT" for m, _p, _j in calls)


async def test_ruleset_worker_apply_puts_full_round_tripped_body(monkeypatch):
    ruleset = _ruleset(["check"])
    worker, calls = _ruleset_worker(
        monkeypatch, dry_run=False, contexts=["hk / lint"], repo_rulesets=[ruleset]
    )
    result = await worker(REPO)
    assert result.tag == protection.Tag.APPLIED_RULESET
    put = [c for c in calls if c[0] == "PUT"]
    assert len(put) == 1
    _method, path, body = put[0]
    assert path == "/repos/hugoh/repo/rulesets/1"
    assert body["bypass_actors"] == ruleset["bypass_actors"]
    assert body["rules"][1]["parameters"]["required_status_checks"] == [
        {"context": "hk / lint", "integration_id": protection.GITHUB_ACTIONS_APP_ID}
    ]


async def test_ruleset_worker_evaluate_mode_is_limited(monkeypatch):
    worker, _calls = _ruleset_worker(
        monkeypatch,
        dry_run=False,
        contexts=["hk / lint"],
        repo_rulesets=[_ruleset(["check"], enforcement="evaluate")],
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED
    assert result.tag == protection.Tag.RULESET_EVALUATE_MODE
    assert "evaluate mode" in result.line


async def test_ruleset_worker_multiple_rulesets_reports_and_skips(monkeypatch):
    worker, calls = _ruleset_worker(
        monkeypatch,
        dry_run=False,
        contexts=["hk / lint"],
        repo_rulesets=[_ruleset(["check"], rid=1), _ruleset(["check"], rid=2)],
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    assert result.tag == protection.Tag.MULTIPLE_RULESETS
    assert "multiple rulesets enforce required checks: 1, 2" in result.line
    assert not any(m == "PUT" for m, _p, _j in calls)


async def test_both_mechanism_writes_classic_and_ruleset(monkeypatch):
    worker, calls = _ruleset_worker(
        monkeypatch,
        dry_run=False,
        contexts=["hk / lint"],
        repo_rulesets=[_ruleset(["hk / lint"])],
        classic_code=200,
    )
    # classic GET returns 200 with empty body -> not up to date -> both PUTs
    result = await worker(REPO)
    assert result.tag == protection.Tag.APPLIED_BOTH
    puts = [p for m, p, _j in calls if m == "PUT"]
    assert any(p.endswith("/protection") for p in puts)
    assert any(p == "/repos/hugoh/repo/rulesets/1" for p in puts)


# ---------------------------------------------------------------------------
# protection sync -- ruleset fallback for plan-gated private repos
# ---------------------------------------------------------------------------


def test_new_ruleset_payload_shape():
    payload = protection.new_ruleset_payload("main", ["hk / lint", "build"])
    assert payload["name"] == protection.MANAGED_RULESET_NAME
    assert payload["target"] == "branch"
    assert payload["enforcement"] == "active"
    assert payload["conditions"]["ref_name"]["include"] == ["~DEFAULT_BRANCH"]
    assert [r["type"] for r in payload["rules"]] == [
        "pull_request",
        "required_status_checks",
        "non_fast_forward",
        "deletion",
    ]
    assert payload["rules"][0]["parameters"]["required_approving_review_count"] == 0
    checks = payload["rules"][1]["parameters"]
    assert checks["strict_required_status_checks_policy"] is True
    assert checks["required_status_checks"] == [
        {"context": "build", "integration_id": protection.GITHUB_ACTIONS_APP_ID},
        {"context": "hk / lint", "integration_id": protection.GITHUB_ACTIONS_APP_ID},
    ]
    assert payload["bypass_actors"] == [
        {
            "actor_type": "RepositoryRole",
            "actor_id": protection.REPO_ADMIN_ROLE_ID,
            "bypass_mode": "always",
        }
    ]


def test_new_ruleset_payload_no_contexts_omits_checks_rule():
    payload = protection.new_ruleset_payload("main", [])
    assert [r["type"] for r in payload["rules"]] == [
        "pull_request",
        "non_fast_forward",
        "deletion",
    ]


def _plan_gated_ruleset_worker(
    monkeypatch,
    *,
    dry_run,
    contexts=("hk / lint",),
    ruleset_listing=(),
    ruleset_list_status=200,
    matching=(),
):
    calls = []
    _patch_branch_protection_lookups(
        monkeypatch, contexts=contexts, matching_rulesets=matching
    )

    async def fake_api_raw(method, path, **kwargs):
        calls.append((method, path, kwargs.get("json")))
        if path.endswith("/protection"):
            return _FakeResponse(403)
        if method == "GET" and path.endswith("/rulesets"):
            if ruleset_list_status != 200:
                return _FakeResponse(ruleset_list_status)
            return _FakeResponseWithJson(200, list(ruleset_listing))
        return _FakeResponse(200)

    monkeypatch.setattr(protection, "api_raw", fake_api_raw)
    worker = protection.make_branch_protection_worker(owner="hugoh", dry_run=dry_run)
    return worker, calls


async def test_plan_gated_worker_creates_ruleset_when_contexts_sampled(monkeypatch):
    worker, calls = _plan_gated_ruleset_worker(
        monkeypatch, dry_run=False, contexts=["hk / lint"]
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert result.tag == protection.Tag.APPLIED_RULESET
    posts = [c for c in calls if c[0] == "POST"]
    assert len(posts) == 1
    _method, path, body = posts[0]
    assert path == "/repos/hugoh/repo/rulesets"
    assert [r["type"] for r in body["rules"]] == [
        "pull_request",
        "required_status_checks",
        "non_fast_forward",
        "deletion",
    ]
    assert body["bypass_actors"][0]["actor_type"] == "RepositoryRole"
    assert "created ruleset -> require: hk / lint" in result.line


async def test_plan_gated_worker_dry_run_reports_would_create_no_post(monkeypatch):
    worker, calls = _plan_gated_ruleset_worker(
        monkeypatch, dry_run=True, contexts=["hk / lint"]
    )
    result = await worker(REPO)
    assert result.status == Status.OK
    assert "would create ruleset -> require: hk / lint" in result.line
    assert not any(m == "POST" for m, _p, _j in calls)


async def test_plan_gated_worker_reports_skip_when_rulesets_also_plan_gated(
    monkeypatch,
):
    # A private repo on a plan without branch protection also can't create
    # repository rulesets -- GET /rulesets 403s. Dry-run must say so, not
    # promise "would create ruleset" (which apply then can't deliver).
    worker, calls = _plan_gated_ruleset_worker(
        monkeypatch, dry_run=True, contexts=["hk / lint"], ruleset_list_status=403
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    assert result.tag == protection.Tag.SKIPPED_NO_PLAN
    assert "plan does not allow branch protection" in result.line
    assert "would create ruleset" not in result.line
    assert not any(m == "POST" for m, _p, _j in calls)


async def test_plan_gated_worker_apply_skips_when_rulesets_also_plan_gated(monkeypatch):
    worker, calls = _plan_gated_ruleset_worker(
        monkeypatch, dry_run=False, contexts=["hk / lint"], ruleset_list_status=403
    )
    result = await worker(REPO)
    assert result.tag == protection.Tag.SKIPPED_NO_PLAN
    assert not any(m == "POST" for m, _p, _j in calls)


async def test_plan_gated_worker_still_skips_when_no_contexts(monkeypatch):
    worker, calls = _plan_gated_ruleset_worker(monkeypatch, dry_run=False, contexts=[])
    result = await worker(REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    assert result.tag == protection.Tag.SKIPPED_NO_PLAN
    assert "plan does not allow branch protection" in result.line
    assert not any(m == "POST" for m, _p, _j in calls)


async def test_plan_gated_worker_idempotent_once_ruleset_exists(monkeypatch):
    worker, calls = _plan_gated_ruleset_worker(
        monkeypatch,
        dry_run=False,
        contexts=["hk / lint"],
        matching=[_ruleset(["hk / lint"])],
    )
    result = await worker(REPO)
    assert result.status == Status.UNCHANGED
    assert not any(m in ("POST", "PUT") for m, _p, _j in calls)


async def test_plan_gated_worker_manual_attention_when_plain_branch_ruleset_exists(
    monkeypatch,
):
    worker, calls = _plan_gated_ruleset_worker(
        monkeypatch,
        dry_run=False,
        contexts=["hk / lint"],
        ruleset_listing=[{"id": 9, "enforcement": "active"}],
    )
    result = await worker(REPO)
    assert result.status == Status.LIMITED_UNCHANGED
    assert result.tag == protection.Tag.RULESET_NO_CHECKS_RULE
    assert not any(m == "POST" for m, _p, _j in calls)
