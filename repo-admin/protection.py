"""Branch-protection engine for `repo_admin.py protection sync`: samples the
required status checks from recent pull requests, reconciles them against
classic branch protection and repository rulesets, and builds per-repo workers.
"""

from __future__ import annotations

import base64
import copy
import enum
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch

import yaml
from lib import (
    GhError,
    Repo,
    RepoResult,
    Status,
    api_json,
    api_raw,
    error_message,
    result_line,
    run_reconcile,
)


class Tag(enum.StrEnum):
    """What `cmd_protection_sync` reports at the end of a run."""

    ATTENTION = "attention"
    RENAME_CANDIDATE = "rename_candidate"
    UNPROTECTED = "unprotected"


# ---------------------------------------------------------------------------
# protection sync
#
# Applies a baseline branch-protection policy (required status checks, PR
# required with 0 approvals, enforce-for-admins, no force-push/deletion) to
# each repo's default branch. Matches the convention already established by
# go-tools' `mise run gh-repo-setup`: required_pull_request_reviews must be
# a non-null object (required_approving_review_count: 0 works) to force
# GitHub's "require a pull request before merging" -- a null value doesn't
# reliably block direct pushes to the branch, only null-vs-object controls
# that, independent of required_status_checks.
#
# Required status check contexts are read from the check runs on the most
# recent pull request's head commit, not the default branch tip: a workflow
# skipped entirely by a path/branch filter never posts a check at all, and
# requiring that context as a merge gate would leave it stuck pending
# forever. (A job skipped via an `if:` condition inside a triggered workflow
# is fine to require -- GitHub reports that as a passing "skipped" check.)
# Sampling an actual PR's check runs avoids picking up the former case.
#
# Only check runs reported by the "github-actions" app are considered:
# third-party apps (DeepSource, Codecov, etc.) aren't defined by the repo
# itself, can be reconfigured or removed outside of this tool's control, and
# shouldn't be able to block merges as a side effect of having run once on a
# PR.
#
# A `*-gate` job (e.g. `ci-gate`: `if: always()`, `needs:` every job that must pass) is the
# stable required check; the jobs it lists in `needs:` are dropped, including the
# `<job> / <inner>` checks of a caller job that uses a reusable workflow.
#
# Even under the "github-actions" app, GitHub-managed setups post checks the
# repo can't edit: CodeQL default setup runs as a synthetic "CodeQL" workflow
# ("Analyze (...)" jobs) and Advanced Security posts a "github-advanced-security"
# check, both from `dynamic/...` workflow paths rather than a file in the repo's
# `.github/workflows/`. Each check run links to its workflow run via a shared
# check-suite id, so a context is kept when either (1) that suite belongs to a
# workflow run whose path is under `.github/workflows/`, or (2) the check name's
# first `" / "`-segment names a job in one of the repo's own workflow files that
# calls a reusable workflow via `uses:`. Signal 2 covers `hk / lint`-style
# checks: a caller job `hk` doing `uses: hugoh/gh-workflows/.../hk.yml` can have
# its check-run attributed to a child workflow run whose path points outside
# `.github/workflows/`, which signal 1 alone would drop as third-party.
#
# The required-checks gate can live in classic branch protection, in a
# repository ruleset's `required_status_checks` rule, or both -- ChecksTarget
# abstracts over that. A ruleset is adopted (its checks rule updated) when it is
# active/evaluate, targets the default branch, and already has a
# `required_status_checks` rule; the whole ruleset object is round-tripped on
# write so `bypass_actors`, `conditions`, and other rules are preserved
# verbatim. `evaluate`-mode, multiple-matching, and org-level rulesets are
# reported (Status.LIMITED) rather than guessed at. New repos with neither
# mechanism still get classic protection.
#
# Private repos on a plan that doesn't expose branch protection return a 403
# ("Upgrade to GitHub Pro..."); those are collected and reported at the end
# rather than treated as a hard failure (unless a ruleset already enforces the
# gate, in which case that ruleset is used).
# ---------------------------------------------------------------------------


def branch_protection_payload(contexts: list[str]) -> dict:
    return {
        "required_status_checks": (
            {"strict": True, "contexts": contexts} if contexts else None
        ),
        "enforce_admins": True,
        "required_pull_request_reviews": {"required_approving_review_count": 0},
        "restrictions": None,
        "allow_force_pushes": False,
        "allow_deletions": False,
    }


def current_protection_contexts(current: dict | None) -> list[str]:
    required_status_checks = (current or {}).get("required_status_checks") or {}
    return sorted(required_status_checks.get("contexts") or [])


def branch_protection_up_to_date(current: dict | None, contexts: list[str]) -> bool:
    current = current or {}
    required_status_checks = current.get("required_status_checks") or {}
    current_contexts = required_status_checks.get("contexts") or []
    if contexts:
        checks_ok = (
            sorted(current_contexts) == sorted(contexts)
            and required_status_checks.get("strict") is True
        )
    else:
        # No known checks to require yet (no PRs, or no check runs on the
        # latest one) -- the baseline (no force-push/deletion, PR required,
        # admins enforced) still applies without gating on specific contexts.
        checks_ok = not current_contexts
    return (
        checks_ok
        and (current.get("enforce_admins") or {}).get("enabled") is True
        and (current.get("allow_force_pushes") or {}).get("enabled") is False
        and (current.get("allow_deletions") or {}).get("enabled") is False
        and (current.get("required_pull_request_reviews") or {}).get(
            "required_approving_review_count"
        )
        == 0
    )


_PR_SAMPLE_SIZE = "5"


async def _recent_pr_head_shas(owner: str, name: str) -> list[str]:
    pulls = await api_json(
        "GET",
        f"/repos/{owner}/{name}/pulls",
        params={
            "state": "all",
            "per_page": _PR_SAMPLE_SIZE,
            "sort": "updated",
            "direction": "desc",
        },
    )
    return [pull["head"]["sha"] for pull in pulls]


_BASE_BRANCH_SAMPLE_SIZE = "5"


async def _base_branch_check_names(
    owner: str, name: str, default_branch: str
) -> set[str]:
    """Names of GitHub Actions check runs seen on recent default-branch commits.

    Used to tell a genuine check rename from GitHub's cross-run bare/prefixed
    naming inconsistency when reconciling required-check contexts.
    """
    commits = await api_json(
        "GET",
        f"/repos/{owner}/{name}/commits",
        params={"sha": default_branch, "per_page": _BASE_BRANCH_SAMPLE_SIZE},
    )
    names: set[str] = set()
    for commit in commits:
        for run in await _github_actions_check_runs(owner, name, commit["sha"]):
            names.add(run["name"])
    return names


async def _github_actions_check_runs(owner: str, name: str, sha: str) -> list[dict]:
    data = await api_json("GET", f"/repos/{owner}/{name}/commits/{sha}/check-runs")
    return [
        run
        for run in data["check_runs"]
        if (run.get("app") or {}).get("slug") == "github-actions"
    ]


async def _own_workflow_check_suite_ids(owner: str, name: str, sha: str) -> set[int]:
    """check-suite ids of workflow runs defined by files in `.github/workflows/`.

    GitHub-managed setups (CodeQL default setup, the Advanced Security findings
    run) execute under synthetic `dynamic/...` paths; their checks shouldn't
    become merge gates the repo can't edit.
    """
    runs = await api_json(
        "GET",
        f"/repos/{owner}/{name}/actions/runs",
        params={"head_sha": sha, "per_page": "100"},
    )
    return {
        run["check_suite_id"]
        for run in runs["workflow_runs"]
        if run["path"].startswith(".github/workflows/")
    }


async def _workflow_docs(owner: str, name: str, ref: str) -> list[dict]:
    """Parsed `.github/workflows/*.y(a)ml` documents at `ref`."""
    listing = await api_raw(
        "GET",
        f"/repos/{owner}/{name}/contents/.github/workflows",
        params={"ref": ref},
    )
    if listing.status_code == 404:
        return []
    if not listing.is_success:
        raise GhError(error_message(listing), status_code=listing.status_code)
    entries = listing.json()
    if not isinstance(entries, list):
        return []

    docs: list[dict] = []
    for entry in entries:
        filename = entry.get("name", "")
        if entry.get("type") != "file" or not filename.endswith((".yml", ".yaml")):
            continue
        blob = await api_json(
            "GET",
            f"/repos/{owner}/{name}/contents/.github/workflows/{filename}",
            params={"ref": ref},
        )
        try:
            content = base64.b64decode(blob["content"]).decode("utf-8")
            doc = yaml.safe_load(content) or {}
        except (ValueError, yaml.YAMLError):
            continue
        if isinstance(doc, dict):
            docs.append(doc)
    return docs


def _own_reusable_job_prefixes(docs: list[dict]) -> set[str]:
    """Job keys / names of jobs in the repo's own `.github/workflows/*.yml`
    that call a reusable workflow via `uses:`.

    A caller job `hk` that does `uses: hugoh/gh-workflows/.github/workflows/hk.yml`
    surfaces on a PR as a check named `hk / <reusable job>` (e.g. `hk / lint`).
    GitHub attributes that check-run's check-suite inconsistently -- sometimes to
    the caller run under `.github/workflows/`, sometimes to a child run whose
    path points at the reusable workflow's own repo -- so `_check_run_contexts`
    also accepts a check as "the repo's own" when its first `" / "`-segment is
    one of these prefixes.
    """
    prefixes: set[str] = set()
    for doc in docs:
        for key, job in (doc.get("jobs") or {}).items():
            if isinstance(job, dict) and isinstance(job.get("uses"), str):
                prefixes.add(key)
                if isinstance(job.get("name"), str):
                    prefixes.add(job["name"])
    return prefixes


_GATE_JOB = re.compile(r"(^|-)gate$")
_MATRIX_SUFFIX = re.compile(r" \(.+\)$")


def _gate_covered_jobs(docs: list[dict]) -> set[str]:
    """Names (matrix suffix stripped) of jobs a `*-gate` job lists in `needs:`.

    The gate is the stable required check; the jobs it aggregates, like
    `anodizer (ubuntu-latest)` and `changes` behind `cross-gate`, are not.
    """
    covered: set[str] = set()
    for doc in docs:
        jobs = {k: v for k, v in (doc.get("jobs") or {}).items() if isinstance(v, dict)}
        for key, job in jobs.items():
            if not _GATE_JOB.search(key):
                continue
            needs = job.get("needs") or []
            for need in [needs] if isinstance(needs, str) else needs:
                label = jobs.get(need, {}).get("name")
                covered.add(
                    _MATRIX_SUFFIX.sub("", label if isinstance(label, str) else need)
                )
    return covered


def _own_reusable_check(name: str, own_reusable_job_prefixes: set[str]) -> bool:
    stripped = _MATRIX_SUFFIX.sub("", name)
    if " / " not in stripped:
        return False
    return stripped.split(" / ", 1)[0] in own_reusable_job_prefixes


async def _check_run_contexts(
    owner: str,
    name: str,
    shas: list[str],
    own_reusable_job_prefixes: set[str] | None = None,
    gate_covered_jobs: set[str] | None = None,
    push_only_jobs: set[str] | None = None,
) -> list[str]:
    """Contexts to require, sampled from the most recent PR's head commit.

    A job that calls a reusable workflow via `uses:` alongside a `needs:`
    dependency reports under two different names depending on outcome: its
    own job id (e.g. "release") when a failed dependency causes it to skip
    before ever invoking the reusable workflow, or a composite name (e.g.
    "release / release") once it actually runs. Landing on a PR where that
    dependency failed would require the skip-only name, which then never
    posts again once the dependency passes -- leaving future PRs stuck
    pending forever. So a bare, skipped name is replaced with a composite
    alias ("<name> / ...") if one shows up, actually run, anywhere in a
    short recent-PR window.
    """
    own_reusable_job_prefixes = own_reusable_job_prefixes or set()
    shas = await _settled_first(owner, name, shas)
    latest_runs = await _github_actions_check_runs(owner, name, shas[0])
    own_suites = await _own_workflow_check_suite_ids(owner, name, shas[0])
    latest_runs = [
        run
        for run in latest_runs
        if run["check_suite"]["id"] in own_suites
        or _own_reusable_check(run["name"], own_reusable_job_prefixes)
    ]
    contexts = {run["name"] for run in latest_runs}
    suspect = {
        run["name"]
        for run in latest_runs
        if run["conclusion"] == "skipped" and " / " not in run["name"]
    }
    if not suspect:
        return _finalize_contexts(contexts, gate_covered_jobs, push_only_jobs)

    for sha in shas[1:]:
        if not suspect:
            break
        for run in await _github_actions_check_runs(owner, name, sha):
            if run["conclusion"] == "skipped":
                continue
            base = run["name"].split(" / ", 1)[0]
            if base in suspect:
                contexts.discard(base)
                contexts.add(run["name"])
                suspect.discard(base)

    return _finalize_contexts(contexts, gate_covered_jobs, push_only_jobs)


def _job_label(key: str, job: dict) -> str:
    label = job.get("name")
    return _MATRIX_SUFFIX.sub("", label if isinstance(label, str) else key)


_NON_PR_EVENT = re.compile(
    r"(github\.)?event_name\s*(==\s*'(push|workflow_dispatch|schedule)'"
    r"|!=\s*'pull_request')"
)


def _never_runs_on_pull_request(condition: str) -> bool:
    """True only when every `||` branch has a `&&` term pinning a non-PR event.

    Anything else (needs.* outputs, parentheses, functions) is assumed able to
    run on a PR.
    """
    expr = condition.strip().removeprefix("${{").removesuffix("}}")
    return all(
        any(_NON_PR_EVENT.fullmatch(term.strip()) for term in branch.split("&&"))
        for branch in expr.split("||")
    )


def _push_only_jobs(docs: list[dict]) -> set[str]:
    """Names of jobs that never run on a pull request.

    A job whose `if` selects push/dispatch events without mentioning
    `pull_request`, plus anything that `needs:` such a job. Their checks show
    up skipped on a PR head and must not become required.
    """
    out: set[str] = set()
    for doc in docs:
        jobs = {k: v for k, v in (doc.get("jobs") or {}).items() if isinstance(v, dict)}
        skipped = {
            k
            for k, job in jobs.items()
            if isinstance(job.get("if"), str) and _never_runs_on_pull_request(job["if"])
        }
        while True:
            more = {
                k
                for k, job in jobs.items()
                if k not in skipped
                and skipped
                & set(
                    [job["needs"]]
                    if isinstance(job.get("needs"), str)
                    else job.get("needs") or []
                )
            }
            if not more:
                break
            skipped |= more
        out |= {_job_label(k, jobs[k]) for k in skipped}
    return out


def _path_filtered_jobs(docs: list[dict]) -> set[str]:
    """Names of jobs in workflows whose `pull_request` trigger is path-filtered.

    Such a job reports only on PRs touching matching paths, so its absence from
    a sampled PR says nothing about whether the check still exists.
    """
    out: set[str] = set()
    for doc in docs:
        triggers = doc.get("on", doc.get(True))
        pull_request = (
            triggers.get("pull_request") if isinstance(triggers, dict) else None
        )
        if not isinstance(pull_request, dict) or not (
            pull_request.get("paths") or pull_request.get("paths-ignore")
        ):
            continue
        jobs = {k: v for k, v in (doc.get("jobs") or {}).items() if isinstance(v, dict)}
        out |= {_job_label(k, job) for k, job in jobs.items()}
    return out


def _keep_path_filtered_checks(
    contexts: list[str], existing: list[str], path_filtered: set[str]
) -> list[str]:
    kept = {
        check
        for check in existing
        if _MATRIX_SUFFIX.sub("", check) in path_filtered
        or check.split(" / ", 1)[0] in path_filtered
    }
    return sorted(set(contexts) | kept)


def _finalize_contexts(
    contexts: set[str],
    gate_covered_jobs: set[str] | None,
    push_only_jobs: set[str] | None,
) -> list[str]:
    contexts = _drop_shadowed_by_wrapper_gate(_collapse_matrix_legs(contexts))
    contexts = {
        name
        for name in contexts
        if _MATRIX_SUFFIX.sub("", name) not in (push_only_jobs or set())
    }
    if any(_GATE_JOB.search(name) for name in contexts):
        covered = gate_covered_jobs or set()
        # A covered job that calls a reusable workflow reports "<job> / <inner>"
        # (e.g. "hk / lint"), so match the leading segment as well as the whole name.
        contexts = {
            name
            for name in contexts
            if _MATRIX_SUFFIX.sub("", name) not in covered
            and _MATRIX_SUFFIX.sub("", name).split(" / ", 1)[0] not in covered
        }
    return sorted(contexts)


async def _settled_first(owner: str, name: str, shas: list[str]) -> list[str]:
    """Move the first sha with no in-progress runs to the front.

    A head sampled mid-run lacks wrapper gates (`cross-gate` posts only once
    its `needs` finish). Falls back to the given order if every sha is running.
    """
    for i, sha in enumerate(shas):
        runs = await _github_actions_check_runs(owner, name, sha)
        if all(run["conclusion"] is not None for run in runs):
            return [sha, *shas[:i], *shas[i + 1 :]]
    return shas


_MATRIX_LEG = re.compile(r"^(?P<prefix>.*?(?: / )?)(?P<job>[^/]+) \(.+\)$")


def _collapse_matrix_legs(contexts: set[str]) -> set[str]:
    """Drop matrix child checks ("jj / test (0.42)") when a sibling gate check
    ("jj / gate", "git-gate") covers them. Matrix leg names carry the varied
    value (a tool version, a runner label) and churn as that value moves, so
    requiring them by name leaves a stale context stuck pending after every
    bump; the gate is a stable stand-in. Without a gate the legs are kept, so
    protection is never silently weakened.
    """
    kept = set()
    for name in contexts:
        match = _MATRIX_LEG.match(name)
        if match and _gate_sibling(match["prefix"], match["job"]) & contexts:
            continue
        kept.add(name)
    return kept


def _drop_shadowed_by_wrapper_gate(contexts: set[str]) -> set[str]:
    """Drop "<job>" and "<job> / ..." checks when a top-level "<job>-gate" wrapper exists.

    A path-filtered caller job `jj` posts its reusable workflow's checks
    ("jj / gate") only when it actually runs, and a bare "jj" when skipped;
    requiring either strands or vacuously satisfies every PR. The
    always-running `jj-gate` wrapper is the stable stand-in.
    """
    jobs = {name.removesuffix("-gate") for name in contexts if name.endswith("-gate")}
    prefixes = tuple(job + " / " for job in jobs)
    return {
        name for name in contexts if name not in jobs and not name.startswith(prefixes)
    }


def _gate_sibling(prefix: str, job: str) -> set[str]:
    return {f"{prefix}gate", f"{prefix}{job}-gate", f"{prefix}{job} / gate"}


def _reconcile_reusable_prefix(
    sampled: list[str],
    existing: list[str],
    base_branch_checks: set[str] | None = None,
    prefer_sampled: bool = False,
) -> list[str]:
    """A `workflow_call` check is reported as `<caller job> / <reusable job>`
    on most runs but sometimes bare `<reusable job>` -- a GitHub inconsistency
    across runs of the same workflow. When a freshly-sampled context is the
    prefix-stripped (or prefixed) form of one already required, keep the
    existing spelling: switching the merge gate to the bare name strands it
    pending, since `main`'s runs report the prefixed name.

    `base_branch_checks`, when given, is the set of check-run names seen on
    recent base-branch commits. If the existing spelling is absent from it but
    the sampled one is present, the check was genuinely renamed (not a per-run
    inconsistency) and the sample wins -- otherwise the stale gate can never be
    satisfied again.

    `prefer_sampled` (the `--adopt-renamed-checks` opt-in) skips the heuristic
    and takes the sampled spelling, for a rename that lives only on an open PR --
    where the base branch still reports the old name and the gate it blocks is
    the very PR that renames the check.
    """
    if not sampled or not existing:
        return sorted(set(sampled))
    out: list[str] = []
    for ctx in sampled:
        if ctx in existing:
            out.append(ctx)
            continue
        candidates = [
            e for e in existing if e.endswith(f" / {ctx}") or ctx.endswith(f" / {e}")
        ]
        equiv = candidates[0] if len(candidates) == 1 else None
        take_sample = (
            equiv is None
            or prefer_sampled
            or _renamed_on_base_branch(ctx, equiv, base_branch_checks)
        )
        out.append(ctx if take_sample else equiv)
    return sorted(set(out))


def _live_unsampled_checks(
    sampled: list[str], existing: list[str], base_branch_checks: set[str]
) -> set[str]:
    """Required checks the PR sample can't see (push-only jobs like `pages` or
    `release`) but that `main` still reports: a rename adoption must keep them.
    """
    return {
        e
        for e in existing
        if e in base_branch_checks
        and e not in sampled
        and not any(e.endswith(f" / {c}") or c.endswith(f" / {e}") for c in sampled)
    }


def _renamed_on_base_branch(
    sampled: str, existing: str, base_branch_checks: set[str] | None
) -> bool:
    return (
        base_branch_checks is not None
        and existing not in base_branch_checks
        and sampled in base_branch_checks
    )


# The GitHub Actions app id on github.com. Pinning a ruleset's required-check
# context to it is the ruleset-mode equivalent of classic mode's "only the
# github-actions app can satisfy this gate" filter.
GITHUB_ACTIONS_APP_ID = 15368

# Name of the branch ruleset this tool creates for a plan-gated private repo
# (see _create_protection_ruleset). Stable so a later run recognises its own
# ruleset via _matching_rulesets rather than creating a second one.
MANAGED_RULESET_NAME = "repo-admin: branch protection"

# GitHub's built-in "Repository admin" base role id, used as a bypass actor on
# the managed ruleset so the account owner keeps direct-push access to the
# default branch while every pull request still goes through the checks gate.
REPO_ADMIN_ROLE_ID = 5

_RULESET_ROUND_TRIP_FIELDS = (
    "name",
    "target",
    "enforcement",
    "conditions",
    "rules",
    "bypass_actors",
)


def _ruleset_ref_matches(conditions: dict, default_branch: str) -> bool:
    ref = (conditions or {}).get("ref_name") or {}
    target = f"refs/heads/{default_branch}"

    def hit(pattern: str) -> bool:
        if pattern in ("~ALL", "~DEFAULT_BRANCH"):
            return True
        return pattern == target or fnmatch(target, pattern)

    include = ref.get("include") or []
    exclude = ref.get("exclude") or []
    return any(hit(p) for p in include) and not any(hit(p) for p in exclude)


def _ruleset_checks_rule(ruleset: dict) -> dict | None:
    for rule in ruleset.get("rules") or []:
        if rule.get("type") == "required_status_checks":
            return rule
    return None


def _ruleset_contexts(ruleset: dict) -> list[str]:
    rule = _ruleset_checks_rule(ruleset)
    if rule is None:
        return []
    checks = (rule.get("parameters") or {}).get("required_status_checks") or []
    return sorted(entry["context"] for entry in checks)


def _ruleset_up_to_date(ruleset: dict, contexts: list[str]) -> bool:
    rule = _ruleset_checks_rule(ruleset)
    if rule is None:
        return False
    params = rule.get("parameters") or {}
    return (
        _ruleset_contexts(ruleset) == sorted(contexts)
        and params.get("strict_required_status_checks_policy") is True
    )


def ruleset_checks_payload(ruleset: dict, contexts: list[str]) -> dict:
    """The whole-object PUT body for a ruleset with only its
    `required_status_checks` rule mutated to require `contexts`.

    Everything else -- `bypass_actors`, `conditions`, other rule types, name,
    enforcement -- is carried through verbatim from the fetched object.
    """
    updated = copy.deepcopy(ruleset)
    rule = _ruleset_checks_rule(updated)
    if rule is None:
        raise ValueError("ruleset has no required_status_checks rule")
    params = rule.setdefault("parameters", {})
    existing = params.get("required_status_checks") or []
    prev_by_context = {entry["context"]: entry for entry in existing}
    changing = sorted(prev_by_context) != sorted(contexts)

    new_entries = []
    for context in sorted(contexts):
        prev = prev_by_context.get(context)
        if prev is not None and "integration_id" in prev:
            new_entries.append(
                {"context": context, "integration_id": prev["integration_id"]}
            )
        elif changing:
            new_entries.append(
                {"context": context, "integration_id": GITHUB_ACTIONS_APP_ID}
            )
        else:
            new_entries.append({"context": context})
    params["required_status_checks"] = new_entries
    params["strict_required_status_checks_policy"] = True
    return {key: updated[key] for key in _RULESET_ROUND_TRIP_FIELDS if key in updated}


def new_ruleset_payload(default_branch: str, contexts: list[str]) -> dict:
    """The POST body for a fresh branch ruleset mirroring the classic baseline:
    PR required (0 approvals), required status checks pinned to the Actions app,
    no force-push, no deletion. The account owner bypasses so direct pushes to
    the default branch still work -- the deliberate difference from the classic
    protection on public repos, which has no bypass.
    """
    rules: list[dict] = [
        {
            "type": "pull_request",
            "parameters": {
                "required_approving_review_count": 0,
                "dismiss_stale_reviews_on_push": False,
                "require_code_owner_review": False,
                "require_last_push_approval": False,
                "required_review_thread_resolution": False,
            },
        }
    ]
    if contexts:
        rules.append(
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": c, "integration_id": GITHUB_ACTIONS_APP_ID}
                        for c in sorted(contexts)
                    ],
                },
            }
        )
    rules += [{"type": "non_fast_forward"}, {"type": "deletion"}]
    return {
        "name": MANAGED_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": rules,
        "bypass_actors": [
            {
                "actor_type": "RepositoryRole",
                "actor_id": REPO_ADMIN_ROLE_ID,
                "bypass_mode": "always",
            }
        ],
    }


@dataclass
class ChecksTarget:
    """Where a repo's required-status-check gate is enforced -- classic branch
    protection, one or more repository rulesets, both, or neither.
    """

    classic: dict | None
    repo_rulesets: list[dict] = field(default_factory=list)
    org_rulesets: list[dict] = field(default_factory=list)

    @property
    def mechanism(self) -> str:
        has_classic = self.classic is not None
        has_ruleset = bool(self.repo_rulesets) or bool(self.org_rulesets)
        if has_classic and has_ruleset:
            return "both"
        if has_ruleset:
            return "ruleset"
        if has_classic:
            return "classic"
        return "none"

    def current_contexts(self) -> list[str]:
        contexts = set(current_protection_contexts(self.classic))
        for ruleset in [*self.repo_rulesets, *self.org_rulesets]:
            contexts.update(_ruleset_contexts(ruleset))
        return sorted(contexts)


def checks_target_up_to_date(target: ChecksTarget, contexts: list[str]) -> bool:
    mechanism = target.mechanism
    if mechanism in ("classic", "both", "none") and not branch_protection_up_to_date(
        target.classic, contexts
    ):
        return False
    if mechanism in ("ruleset", "both"):
        for ruleset in target.repo_rulesets:
            if not _ruleset_up_to_date(ruleset, contexts):
                return False
    for ruleset in target.org_rulesets:
        if _ruleset_contexts(ruleset) != sorted(contexts):
            return False
    return True


async def _matching_rulesets(
    owner: str, name: str, default_branch: str
) -> tuple[list[dict], list[dict]]:
    """`(repo_rulesets, org_rulesets)` -- active/evaluate branch rulesets that
    target the default branch and carry a `required_status_checks` rule,
    fetched as full objects. Org-level rulesets can't be edited by a
    repo-scoped PUT; they're returned separately so callers can report them.
    """
    listing = await api_raw(
        "GET",
        f"/repos/{owner}/{name}/rulesets",
        params={"includes_parents": "true", "targets": "branch"},
    )
    if listing.status_code in (403, 404):
        return [], []
    if not listing.is_success:
        raise GhError(error_message(listing), status_code=listing.status_code)
    summaries = listing.json()
    if not isinstance(summaries, list):
        return [], []

    repo_rulesets: list[dict] = []
    org_rulesets: list[dict] = []
    for summary in summaries:
        if summary.get("enforcement") not in ("active", "evaluate"):
            continue
        detail = await api_raw("GET", f"/repos/{owner}/{name}/rulesets/{summary['id']}")
        if not detail.is_success:
            continue
        ruleset = detail.json()
        if not isinstance(ruleset, dict):
            continue
        ruleset.setdefault("id", summary.get("id"))
        if not _ruleset_ref_matches(ruleset.get("conditions") or {}, default_branch):
            continue
        if _ruleset_checks_rule(ruleset) is None:
            continue
        source_type = ruleset.get("source_type") or summary.get("source_type")
        if source_type == "Organization":
            org_rulesets.append(ruleset)
        else:
            repo_rulesets.append(ruleset)
    return repo_rulesets, org_rulesets


async def _put_ruleset_checks(
    owner: str, name: str, ruleset: dict, contexts: list[str]
) -> None:
    payload = ruleset_checks_payload(ruleset, contexts)
    response = await api_raw(
        "PUT", f"/repos/{owner}/{name}/rulesets/{ruleset['id']}", json=payload
    )
    if not response.is_success:
        raise GhError(error_message(response), status_code=response.status_code)


def _attention_result(repo: Repo, detail: str) -> RepoResult:
    status = Status.LIMITED_UNCHANGED
    return RepoResult(
        repo, result_line(repo.name, detail, status), status, tag=Tag.ATTENTION
    )


def _plan_gated_result(repo: Repo) -> RepoResult:
    status = Status.LIMITED_UNCHANGED
    detail = "private repo, plan disallows protection"
    return RepoResult(repo, result_line(repo.name, detail, status), status)


async def _ruleset_creation_blocker(owner: str, repo: Repo) -> RepoResult | None:
    """A plan-gated private repo can't use classic branch protection, but
    repository rulesets are available on *some* plans where it isn't, so one
    is created as a fallback. Returns why that isn't possible -- the plan
    gates rulesets too (`GET /rulesets` -> 403), or a branch ruleset without a
    required-checks rule already exists -- or None when creation can proceed.
    Once created, a later run finds the ruleset via `_matching_rulesets` and
    takes the normal ruleset path, so this only ever creates.
    """
    listing = await api_raw(
        "GET", f"/repos/{owner}/{repo.name}/rulesets", params={"targets": "branch"}
    )
    if listing.status_code in (403, 404):
        return _plan_gated_result(repo)
    summaries = listing.json() if listing.is_success else None
    if isinstance(summaries, list) and any(
        s.get("enforcement") in ("active", "evaluate") for s in summaries
    ):
        return _attention_result(
            repo, "plan-gated; a branch ruleset lacks a checks rule -- add it manually"
        )
    return None


async def _create_protection_ruleset(
    owner: str, repo: Repo, contexts: list[str]
) -> bool:
    response = await api_raw(
        "POST",
        f"/repos/{owner}/{repo.name}/rulesets",
        json=new_ruleset_payload(repo.default_branch, contexts),
    )
    if response.status_code in (403, 404):
        return False
    if not response.is_success:
        raise GhError(error_message(response), status_code=response.status_code)
    return True


async def _sample_contexts(
    owner: str, repo: Repo, pr_head_shas: list[str]
) -> tuple[list[str], set[str]]:
    """`(sampled contexts, path-filtered job names)`."""
    docs = await _workflow_docs(owner, repo.name, repo.default_branch)
    contexts = await _check_run_contexts(
        owner,
        repo.name,
        pr_head_shas,
        _own_reusable_job_prefixes(docs),
        _gate_covered_jobs(docs),
        _push_only_jobs(docs),
    )
    return contexts, _path_filtered_jobs(docs)


@dataclass
class _Reconciled:
    contexts: list[str]
    notes: list[str] = field(default_factory=list)
    rename_candidate: bool = False


async def _reconcile_with_existing(
    owner: str,
    repo: Repo,
    sampled: list[str],
    existing: list[str],
    *,
    adopt_renamed_checks: bool,
) -> _Reconciled:
    """Settles which spelling of each required check wins between a fresh PR
    sample and what's already required, consulting the default branch only
    when the two disagree.
    """
    sampled_sorted = sorted(set(sampled))
    if _reconcile_reusable_prefix(sampled, existing) == sampled_sorted:
        return _Reconciled(sampled)

    base_branch_checks = await _base_branch_check_names(
        owner, repo.name, repo.default_branch
    )
    reconciled = _reconcile_reusable_prefix(
        sampled,
        existing,
        base_branch_checks,
        prefer_sampled=adopt_renamed_checks,
    )
    live = _live_unsampled_checks(sampled, existing, base_branch_checks)
    contexts = sorted(set(reconciled) | live)
    if reconciled == sampled_sorted:
        return _Reconciled(contexts)

    kept = sorted(set(reconciled) - set(sampled))
    note = (
        f"kept {', '.join(kept)}, PR shows {', '.join(sampled_sorted)} "
        "(--adopt-renamed-checks if renamed)"
    )
    return _Reconciled(contexts, [note], rename_candidate=True)


@dataclass
class _Plan:
    repo: Repo
    target: ChecksTarget
    existing: list[str]
    contexts: list[str]
    notes: list[str] = field(default_factory=list)
    stale_retained: bool = False
    rename_candidate: bool = False
    create_ruleset: bool = False
    final: RepoResult | None = None

    @property
    def up_to_date(self) -> bool:
        return checks_target_up_to_date(self.target, self.contexts)

    @property
    def evaluate_mode(self) -> bool:
        return any(
            rs.get("enforcement") == "evaluate" for rs in self.target.repo_rulesets
        )

    @property
    def tag(self) -> Tag | None:
        if self.evaluate_mode:
            return Tag.ATTENTION
        return Tag.RENAME_CANDIDATE if self.rename_candidate else None


async def _classic_protection(owner: str, repo: Repo) -> tuple[dict | None, bool]:
    """`(current protection, plan_gated)` for the default branch."""
    response = await api_raw(
        "GET",
        f"/repos/{owner}/{repo.name}/branches/{repo.default_branch}/protection",
    )
    if response.status_code in (403, 404):
        return None, response.status_code == 403
    if not response.is_success:
        raise GhError(error_message(response), status_code=response.status_code)
    return response.json(), False


async def _plan_protection(
    owner: str,
    repo: Repo,
    *,
    clear_stale_checks: bool,
    adopt_renamed_checks: bool,
) -> _Plan:
    """Reads a repo's state and decides what protection it should end up with.

    Contexts to require come from a recent PR's check runs. Without any PR
    (or any check runs on the latest one) a repo that already requires checks
    keeps them rather than having the merge gate silently cleared;
    --clear-stale-checks opts into dropping them. With nothing to keep, the
    baseline (PR required, no force-push/deletion, admins enforced) still
    applies without gating on specific checks.
    """
    pr_head_shas = await _recent_pr_head_shas(owner, repo.name)
    sampled, path_filtered = (
        await _sample_contexts(owner, repo, pr_head_shas)
        if pr_head_shas
        else ([], set())
    )
    classic, plan_gated = await _classic_protection(owner, repo)
    repo_rulesets, org_rulesets = await _matching_rulesets(
        owner, repo.name, repo.default_branch
    )
    target = ChecksTarget(
        classic=classic, repo_rulesets=repo_rulesets, org_rulesets=org_rulesets
    )
    plan = _Plan(repo, target, target.current_contexts(), sampled)

    if plan_gated and target.mechanism != "ruleset":
        if not sampled:
            plan.final = _plan_gated_result(repo)
        else:
            plan.final = await _ruleset_creation_blocker(owner, repo)
            plan.create_ruleset = plan.final is None
        return plan

    if sampled and plan.existing:
        reconciled = await _reconcile_with_existing(
            owner,
            repo,
            sampled,
            plan.existing,
            adopt_renamed_checks=adopt_renamed_checks,
        )
        plan.contexts = reconciled.contexts
        plan.notes += reconciled.notes
        plan.rename_candidate = reconciled.rename_candidate
        plan.stale_retained = reconciled.rename_candidate

    if sampled:
        plan.contexts = _keep_path_filtered_checks(
            plan.contexts, plan.existing, path_filtered
        )

    if not plan.contexts:
        plan.notes.append(
            "no PRs yet" if not pr_head_shas else "no checks on latest PR"
        )
        if plan.existing and not clear_stale_checks:
            plan.contexts = plan.existing
            plan.stale_retained = True
            plan.notes.append("kept existing (--clear-stale-checks to drop)")

    plan.final = _unmanageable_rulesets(plan)
    return plan


def _unmanageable_rulesets(plan: _Plan) -> RepoResult | None:
    suffix = "".join(f"; {note}" for note in plan.notes)
    if len(plan.target.repo_rulesets) > 1:
        ids = ", ".join(sorted(str(rs["id"]) for rs in plan.target.repo_rulesets))
        detail = f"multiple rulesets enforce checks ({ids}) -- resolve manually"
        return _attention_result(plan.repo, detail + suffix)
    if plan.target.org_rulesets and not plan.up_to_date:
        ids = ", ".join(str(rs["id"]) for rs in plan.target.org_rulesets)
        detail = f"org ruleset {ids} enforces checks; not managed here"
        return _attention_result(plan.repo, detail + suffix)
    return None


_MECHANISM_LABEL = {
    "none": "",
    "classic": "",
    "ruleset": "ruleset",
    "both": "classic + ruleset",
}


def _changes(existing: list[str], contexts: list[str]) -> str:
    added = [f"+{c}" for c in sorted(set(contexts) - set(existing))]
    removed = [f"-{c}" for c in sorted(set(existing) - set(contexts))]
    return ", ".join(added + removed) or "baseline settings"


def _result(plan: _Plan, *, applied: bool) -> RepoResult:
    limited = plan.stale_retained or plan.evaluate_mode
    notes = [*plan.notes]
    if plan.evaluate_mode:
        notes.append("evaluate mode, not enforcing")
    suffix = "".join(f"; {note}" for note in notes)

    if plan.up_to_date:
        status = Status.LIMITED_UNCHANGED if limited else Status.UNCHANGED
        count = len(plan.contexts)
        label = _MECHANISM_LABEL[plan.target.mechanism]
        detail = (f"{label}: " if label else "") + (
            f"{count} required check{'s' if count != 1 else ''}"
            if count
            else "no required checks"
        )
    else:
        status = Status.LIMITED if limited else Status.OK
        detail = _change_description(plan, applied=applied)
    return RepoResult(
        plan.repo,
        result_line(plan.repo.name, detail + suffix, status),
        status,
        tag=plan.tag,
    )


def _change_description(plan: _Plan, *, applied: bool) -> str:
    changes = _changes(plan.existing, plan.contexts)
    if plan.create_ruleset:
        return f"{'created' if applied else 'would create'} ruleset: {changes}"
    mechanism = plan.target.mechanism
    if mechanism == "none":
        return f"{'protected' if applied else 'would protect'}: {changes}"
    label = _MECHANISM_LABEL[mechanism]
    verb = "updated" if applied else "would update"
    return f"{verb} {label}: {changes}" if label else f"{verb}: {changes}"


async def _apply_plan(owner: str, plan: _Plan) -> RepoResult:
    repo, mechanism = plan.repo, plan.target.mechanism
    if plan.create_ruleset:
        if not await _create_protection_ruleset(owner, repo, plan.contexts):
            return _plan_gated_result(repo)
    elif not plan.up_to_date:
        if mechanism in ("ruleset", "both"):
            if mechanism == "both":
                await _put_classic_protection(owner, repo, plan.contexts)
            for ruleset in plan.target.repo_rulesets:
                await _put_ruleset_checks(owner, repo.name, ruleset, plan.contexts)
        elif not await _put_classic_protection(owner, repo, plan.contexts):
            return _plan_gated_result(repo)
    return _result(plan, applied=True)


async def _put_classic_protection(owner: str, repo: Repo, contexts: list[str]) -> bool:
    """False when the plan gates classic protection."""
    response = await api_raw(
        "PUT",
        f"/repos/{owner}/{repo.name}/branches/{repo.default_branch}/protection",
        json=branch_protection_payload(contexts),
    )
    if response.status_code == 403:
        return False
    if not response.is_success:
        raise GhError(error_message(response), status_code=response.status_code)
    return True


def make_branch_protection_worker(
    owner: str,
    dry_run: bool,
    clear_stale_checks: bool = False,
    adopt_renamed_checks: bool = False,
):
    async def worker(repo: Repo) -> RepoResult:
        async def fetch() -> _Plan:
            return await _plan_protection(
                owner,
                repo,
                clear_stale_checks=clear_stale_checks,
                adopt_renamed_checks=adopt_renamed_checks,
            )

        def plan_result(plan: _Plan) -> RepoResult:
            return plan.final or _result(plan, applied=False)

        async def apply_result(plan: _Plan) -> RepoResult:
            return plan.final or await _apply_plan(owner, plan)

        return await run_reconcile(
            dry_run=dry_run,
            fetch=fetch,
            plan_result=plan_result,
            apply_result=apply_result,
        )

    return worker


def make_branch_unprotect_worker(owner: str, dry_run: bool):
    """Removes classic branch protection from a repo listed in
    branch-protection-exclude.yaml. Being excluded only keeps `protection
    sync` from applying protection going forward -- a repo protected before
    it was added to the exclude file (or added there by mistake and fixed)
    would otherwise stay protected forever, since nothing else ever calls
    the API to remove it.

    # ponytail: classic protection only, no ruleset teardown -- excluded
    # repos are meant to have no CI/PR workflow and haven't needed one;
    # add ruleset removal if one of them ever gets one.
    """
    path = lambda repo: (
        f"/repos/{owner}/{repo.name}/branches/{repo.default_branch}/protection"
    )

    async def worker(repo: Repo) -> RepoResult:
        response = await api_raw("GET", path(repo))
        if response.status_code == 404:
            line = result_line(
                repo.name, "already unprotected (excluded)", Status.UNCHANGED
            )
            return RepoResult(repo, line, Status.UNCHANGED)
        if not response.is_success:
            raise GhError(error_message(response), status_code=response.status_code)

        if not dry_run:
            deleted = await api_raw("DELETE", path(repo))
            if not deleted.is_success:
                raise GhError(error_message(deleted), status_code=deleted.status_code)

        verb = "would remove" if dry_run else "removed"
        line = result_line(repo.name, f"{verb} protection (excluded)", Status.OK)
        return RepoResult(repo, line, Status.OK, tag=Tag.UNPROTECTED)

    return worker
