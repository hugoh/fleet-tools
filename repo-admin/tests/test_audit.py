import audit


def wf(**jobs):
    return {"jobs": jobs}


def gated():
    return wf(
        hk={"uses": "x/hk.yml@a"},
        **{
            "ci-gate": {"needs": ["hk"]},
            "release": {"needs": "ci-gate"},
            "publish": {"needs": "release"},
        },
    )


def test_a_release_behind_a_gate_has_no_findings():
    report = audit.audit_workflows([gated()], required=["ci-gate", "semantic-pr"])
    assert report == audit.RepoAudit()


def test_a_release_with_no_needs_is_ungated():
    report = audit.audit_workflows([wf(hk={}, release={})], required=["hk"])
    assert report.ungated == ["release"]
    assert report.needs_gated == []


def test_a_release_that_needs_checks_but_no_gate_is_only_informational():
    doc = wf(plan={}, hk={}, test={}, tag={"needs": ["plan", "hk", "test"]})
    report = audit.audit_workflows([doc], required=[])
    assert report.needs_gated == ["tag"]
    assert report.ungated == []


def test_the_gate_counts_transitively():
    doc = wf(
        hk={},
        **{"ci-gate": {"needs": ["hk"]}},
        build={"needs": "ci-gate"},
        release={"needs": ["build"]},
    )
    assert audit.audit_workflows([doc], required=["ci-gate"]).ungated == []


def test_publish_and_reusable_release_calls_are_release_jobs():
    doc = wf(
        **{
            "publish-pypi": {},
            "cut": {"uses": "hugoh/gh-workflows/.github/workflows/release.yml@abc"},
        },
    )
    report = audit.audit_workflows([doc], required=[])
    assert report.ungated == ["cut", "publish-pypi"]


def test_non_release_jobs_are_ignored():
    assert audit.audit_workflows([wf(hk={}, docs={})], required=[]) == audit.RepoAudit()


def test_a_ci_gate_that_is_not_required_is_flagged():
    report = audit.audit_workflows([gated()], required=["semantic-pr"])
    assert report.gate_not_required is True


def test_a_gate_with_another_name_is_not_flagged_as_not_required():
    doc = wf(hk={}, **{"cross-gate": {"needs": ["hk"]}})
    assert audit.audit_workflows([doc], required=[]).gate_not_required is False


def test_jobs_outside_the_gate_are_listed():
    doc = wf(
        hk={},
        lint2={},
        **{"ci-gate": {"needs": ["hk"]}},
        release={"needs": "ci-gate"},
    )
    assert audit.audit_workflows([doc], required=["ci-gate"]).unlisted == ["lint2"]


def test_downstream_jobs_are_not_outside_the_gate():
    assert audit.audit_workflows([gated()], required=["ci-gate"]).unlisted == []


def run(workflow_id, name, conclusion, path=".github/workflows/ci.yml"):
    return {
        "workflow_id": workflow_id,
        "name": name,
        "conclusion": conclusion,
        "path": path,
    }


def test_a_workflow_whose_latest_run_failed_is_red():
    runs = [run(1, "ci", "failure"), run(1, "ci", "success")]
    assert audit.red_workflows(runs) == ["ci"]


def test_an_old_failure_behind_a_newer_success_is_not_red():
    runs = [run(1, "ci", "success"), run(1, "ci", "failure")]
    assert audit.red_workflows(runs) == []


def test_cancelled_runs_do_not_decide_the_state():
    runs = [run(1, "ci", "cancelled"), run(1, "ci", "success")]
    assert audit.red_workflows(runs) == []


def test_github_managed_dynamic_workflows_are_ignored():
    runs = [run(2, "CodeQL", "failure", path="dynamic/github-code-scanning/codeql")]
    assert audit.red_workflows(runs) == []


def test_each_workflow_is_judged_on_its_own_latest_run():
    runs = [run(1, "ci", "success"), run(2, "release", "failure")]
    assert audit.red_workflows(runs) == ["release"]


def test_summary_lines_name_each_repo_and_skip_clean_ones():
    audits = {
        "clean": audit.RepoAudit(),
        "a": audit.RepoAudit(ungated=["release"]),
        "b": audit.RepoAudit(needs_gated=["tag"], gate_not_required=True),
        "c": audit.RepoAudit(unlisted=["pages"], red=["ci", "release"]),
    }
    assert audit.summary_lines(audits) == [
        "Release not behind a gate: a (release)",
        "Release gated only by needs on checks (no ci-gate): b (tag)",
        "ci-gate exists but is not required: b",
        "Jobs outside the gate: c (pages)",
        "Red default branch: c (ci, release)",
    ]


def test_summary_lines_are_empty_when_everything_is_clean():
    assert audit.summary_lines({"clean": audit.RepoAudit()}) == []


def test_a_reusable_only_workflow_is_gated_by_its_caller_not_audited():
    reusable = {"on": {"workflow_call": {}}, "jobs": {"release": {}}}
    assert audit.audit_workflows([reusable], required=[]) == audit.RepoAudit()


def test_the_yaml_on_key_parsed_as_true_is_understood():
    reusable = {True: {"workflow_call": None}, "jobs": {"release": {}}}
    assert audit.audit_workflows([reusable], required=[]) == audit.RepoAudit()


def test_a_workflow_with_its_own_triggers_is_audited_even_if_callable():
    both = {"on": {"push": {}, "workflow_call": {}}, "jobs": {"release": {}}}
    assert audit.audit_workflows([both], required=[]).ungated == ["release"]


def test_runs_of_deleted_workflows_do_not_make_the_branch_red():
    runs = [run(1, "Tests", "failure"), run(2, "ci", "success")]
    assert audit.red_workflows(runs, active={2}) == []
    assert audit.red_workflows(runs, active={1, 2}) == ["Tests"]
