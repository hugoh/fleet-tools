"""Bulk-applies account-wide GitHub repo settings across hugoh's non-archived
repos, via the GitHub REST API (authenticated through `gh auth token`).

Usage: repo_admin.py <resource> <verb> [repo ...] [--dry-run] [--verbose] [--skip name1,name2]

  repos    list                 list repos as a table: name, default branch,
                                 private, fork
  repo     scaffold PATH        render a new repo's baseline files (hk.pkl,
                                 mise.toml, .renovaterc.json, workflow callers)
                                 from templates/ — see `repo scaffold --help`
  merge    sync                 enable auto-merge, delete-branch-on-merge,
                                 and PR-branch auto-update; set the squash
                                 subject to the PR title where semantic-pr
                                 is a required check
  features sync                 set issues/wiki/projects/discussions per
                                 config/features.yaml (fleet default plus
                                 per-repo overrides)
  protection sync               apply a baseline branch-protection policy to
                                 each repo's default branch
  security sync                 enable free, native GitHub security features
  sync                          run merge/features/protection/security/pages sync, in
                                 that order
  pages    status               list repos with GitHub Pages enabled and
                                 their custom domain, flagging ones missing
                                 from config/pages-domains.yaml
  pages    sync [--enable]      set each repo's GitHub Pages custom domain
                                 and homepage URL, from the mapping in
                                 config/pages-domains.yaml; --enable also
                                 turns Pages on where it's missing
  pages    disable REPO...      delete the GitHub Pages site of repos no
                                 longer in config/pages-domains.yaml
  pages    unset-url REPO...    clear the homepage URL of such repos
  pages    config --domain D    print config/pages-domains.yaml entries to
                                 stdout for a base domain, for the given
                                 repos or, if none given, repos `pages
                                 status` would flag as unmapped
  secrets  sync                 push GitHub Actions secrets to each target
                                 repo -- name, targets and values all from
                                 sops-encrypted config/secrets.enc.yaml
  secrets  edit                 open config/secrets.enc.yaml in `sops` for
                                 interactive editing
  variables sync                push GitHub Actions variables, like secrets
                                 sync but from config/variables.{yaml,enc.yaml}
                                 (variable name -> repos stays plaintext)
  variables edit                open config/variables.enc.yaml in `sops`,
                                 seeding it from config/variables.yaml
  config   bootstrap REPO       add REPO to config/secrets.enc.yaml and
                                 config/variables.yaml from the secrets.*/
                                 vars.* its workflows reference, then prompt
                                 for missing values
  activity                      rank repos by recent commit activity
                                 (private+public and public-only tables),
                                 see activity.py --help for its knobs

Every `<resource> <verb>` accepts trailing repo names to scope to a subset
(default: every repo); `--skip name1,name2` excludes instead. Forks are
excluded by default -- except those listed in config/forks-include.yaml; edit
that file to add more, or override per-run with GH_INCLUDE_FORKS
(comma-separated). GH_OWNER overrides the default owner (the authenticated
account); GH_JOBS controls parallelism (default 12). Run a mutating command
with --dry-run
first and review the output; `--verbose` shows every repo, not just the
ones that changed.
"""

from __future__ import annotations

import argparse
import asyncio
import enum
import sys
from collections.abc import Callable
from dataclasses import dataclass
from getpass import getpass

import activity
import audit
import lib
import protection
import scaffold
import yaml
from lib import (
    DEFAULT_JOBS,
    GhError,
    GhRateLimitError,
    Repo,
    RepoResult,
    Status,
    api_json,
    api_raw,
    as_set,
    classify_status,
    default_branch_protection_exclude,
    default_owner,
    default_required_check_ignore,
    error_message,
    list_repos,
    partition_fields,
    result_line,
    run_parallel,
    run_reconcile,
    summary_status,
    unavailable_suffix,
)
from rich.table import Table


class Tag(enum.StrEnum):
    """Per-command bookkeeping for end-of-run summaries -- distinct from
    Status, which is the shared display concept in lib.py.
    """

    UNAVAILABLE = "unavailable"


async def list_repos_for_args(
    args: argparse.Namespace, *, extra_skip: set[str] | None = None
) -> list[Repo]:
    skip = as_set(args.skip) or set()
    if extra_skip:
        skip |= extra_skip
    only = set(args.repos) or None
    return await list_repos(
        await default_owner(), only=only, skip=skip, require_only_match=bool(only)
    )


# ---------------------------------------------------------------------------
# repos list
# ---------------------------------------------------------------------------


async def cmd_repos_list(args: argparse.Namespace) -> int:
    with lib.progress_bar(transient=True) as progress:
        progress.add_task("Fetching repos...", total=None)
        repos = await list_repos_for_args(args)

    table = Table()
    table.add_column("NAME")
    table.add_column("DEFAULT BRANCH")
    table.add_column("PRIVATE")
    table.add_column("FORK")
    for r in repos:
        table.add_row(
            r.name, r.default_branch, str(r.is_private).lower(), str(r.is_fork).lower()
        )
    lib.console.print(table)
    return 0


# ---------------------------------------------------------------------------
# merge sync
#
# Enables auto-merge, delete-branch-on-merge, and PR-branch auto-update. The
# last one matters because branch protection requires PR branches to be up
# to date with the base branch (`strict: true`) -- without auto-update,
# auto-merge PRs get stuck needing a manual "Update branch" click whenever
# another PR merges first.
#
# allow_auto_merge on a private repo silently no-ops on this account's plan
# (private-repo auto-merge needs GitHub Pro/Team/Enterprise) -- confirmed by
# a live PATCH against a private repo returning 200 with the field still
# false. GET always reports the real current value, so dry-run can't tell
# this apart from "would enable" without attempting the write; instead it's
# reported as unavailable, the same way security-features reports its own
# plan-gated fields.
# ---------------------------------------------------------------------------

MERGE_SETTINGS_FIELDS = [
    "allow_auto_merge",
    "delete_branch_on_merge",
    "allow_update_branch",
]


def _merge_gated_fields(*, is_private: bool) -> list[str]:
    return ["allow_auto_merge"] if is_private else []


async def _merge_settings(owner: str, name: str) -> dict:
    data = await api_json("GET", f"/repos/{owner}/{name}")
    return {field: data[field] for field in MERGE_SETTINGS_FIELDS}


def merge_settings_at_target(settings: dict) -> bool:
    return all(settings[field] for field in MERGE_SETTINGS_FIELDS)


def merge_settings_summarize(current: dict, *, is_private: bool = False) -> dict:
    gated = set(_merge_gated_fields(is_private=is_private))
    return partition_fields(
        {
            field: (bool(current[field]), field not in gated)
            for field in MERGE_SETTINGS_FIELDS
        }
    )


def merge_settings_dry_run_line(
    name: str, current: dict, status: Status, *, is_private: bool = False
) -> str:
    summary = merge_settings_summarize(current, is_private=is_private)
    would_enable, unavailable = summary["would_enable"], summary["unavailable"]
    detail = (
        str(current) if not would_enable else f"would enable: {', '.join(would_enable)}"
    )
    return result_line(name, detail + unavailable_suffix(unavailable), status)


def merge_settings_apply_line(
    name: str, before: dict, after: dict, status: Status
) -> str:
    detail = str(after) if before == after else f"{before} -> {after}"
    return result_line(name, detail, status)


def make_merge_settings_worker(owner: str, dry_run: bool):
    async def worker(repo: Repo) -> RepoResult:
        def plan_result(current: dict) -> RepoResult:
            status = summary_status(
                merge_settings_summarize(current, is_private=repo.is_private)
            )
            return RepoResult(
                repo,
                merge_settings_dry_run_line(
                    repo.name, current, status, is_private=repo.is_private
                ),
                status,
            )

        async def apply_result(before: dict) -> RepoResult:
            await api_json(
                "PATCH",
                f"/repos/{owner}/{repo.name}",
                json={field: True for field in MERGE_SETTINGS_FIELDS},
            )
            after = await _merge_settings(owner, repo.name)
            status = classify_status(
                at_target=merge_settings_at_target(after), changed=before != after
            )
            return RepoResult(
                repo,
                merge_settings_apply_line(repo.name, before, after, status),
                status,
            )

        return await run_reconcile(
            dry_run=dry_run,
            fetch=lambda: _merge_settings(owner, repo.name),
            plan_result=plan_result,
            apply_result=apply_result,
        )

    return worker


# ---------------------------------------------------------------------------
# squash-merge commit title
#
# GitHub's default squash-merge subject is "<PR title> (#<n>)" only for a
# single-commit PR; multi-commit PRs fall back to the branch name. Setting
# squash_merge_commit_title=PR_TITLE makes the PR title the squash subject
# unconditionally -- worth doing only where that title is linted into
# Conventional-Commit form, i.e. where the `semantic-pr` reusable workflow's
# check already gates merges on the default branch. Those repos are also made
# squash-only (merge commits and rebase merges off), since only the squash
# path uses the linted title. The meta `sync` runs
# this after `protection sync`, so a repo gets it in the same run that makes
# `semantic-pr` required, with no separate opt-in list to maintain.
# ---------------------------------------------------------------------------

SQUASH_MERGE_TARGET = {
    "squash_merge_commit_title": "PR_TITLE",
    "squash_merge_commit_message": "COMMIT_MESSAGES",
    "allow_squash_merge": True,
    "allow_merge_commit": False,
    "allow_rebase_merge": False,
}


def _has_semantic_pr_check(contexts: list[str]) -> bool:
    """True when `semantic-pr` gates merges -- as a bare context, or as the
    `<caller job> / <reusable job>` form GitHub reports for a `uses:` job.
    """
    return any(c == "semantic-pr" or c.startswith("semantic-pr / ") for c in contexts)


def squash_title_at_target(current: dict) -> bool:
    return all(current.get(key) == value for key, value in SQUASH_MERGE_TARGET.items())


def squash_title_line(
    name: str, before: dict, after: dict | None, status: Status, *, applies: bool
) -> str:
    if not applies:
        return result_line(name, "semantic-pr not a required check", status)
    if after is None:
        detail = (
            str(before)
            if squash_title_at_target(before)
            else "would set: "
            + ", ".join(f"{k}={v}" for k, v in SQUASH_MERGE_TARGET.items())
        )
    else:
        detail = str(after) if before == after else f"{before} -> {after}"
    return result_line(name, detail, status)


async def _squash_settings(owner: str, name: str) -> dict:
    data = await api_json("GET", f"/repos/{owner}/{name}")
    return {key: data.get(key) for key in SQUASH_MERGE_TARGET}


async def _semantic_pr_required(owner: str, name: str, default_branch: str) -> bool:
    response = await api_raw(
        "GET", f"/repos/{owner}/{name}/branches/{default_branch}/protection"
    )
    if response.status_code in (403, 404):
        classic = None
    elif response.is_success:
        classic = response.json()
    else:
        raise GhError(error_message(response), status_code=response.status_code)
    repo_rulesets, org_rulesets = await protection._matching_rulesets(
        owner, name, default_branch
    )
    contexts = protection.ChecksTarget(
        classic=classic, repo_rulesets=repo_rulesets, org_rulesets=org_rulesets
    ).current_contexts()
    return _has_semantic_pr_check(contexts)


@dataclass
class _SquashTitleState:
    current: dict
    applies: bool


def make_squash_title_worker(owner: str, dry_run: bool):
    async def worker(repo: Repo) -> RepoResult:
        async def fetch() -> _SquashTitleState:
            current, applies = await asyncio.gather(
                _squash_settings(owner, repo.name),
                _semantic_pr_required(owner, repo.name, repo.default_branch),
            )
            return _SquashTitleState(current, applies)

        def quiet(state: _SquashTitleState) -> bool:
            return not state.applies or squash_title_at_target(state.current)

        def plan_result(state: _SquashTitleState) -> RepoResult:
            status = Status.UNCHANGED if quiet(state) else Status.OK
            return RepoResult(
                repo,
                squash_title_line(
                    repo.name, state.current, None, status, applies=state.applies
                ),
                status,
            )

        async def apply_result(state: _SquashTitleState) -> RepoResult:
            if quiet(state):
                return RepoResult(
                    repo,
                    squash_title_line(
                        repo.name,
                        state.current,
                        state.current,
                        Status.UNCHANGED,
                        applies=state.applies,
                    ),
                    Status.UNCHANGED,
                )
            await api_json(
                "PATCH", f"/repos/{owner}/{repo.name}", json=dict(SQUASH_MERGE_TARGET)
            )
            after = await _squash_settings(owner, repo.name)
            status = classify_status(
                at_target=squash_title_at_target(after), changed=state.current != after
            )
            return RepoResult(
                repo,
                squash_title_line(
                    repo.name, state.current, after, status, applies=True
                ),
                status,
            )

        return await run_reconcile(
            dry_run=dry_run,
            fetch=fetch,
            plan_result=plan_result,
            apply_result=apply_result,
        )

    return worker


async def _run_worker_sync(args: argparse.Namespace, make_worker) -> int:
    repos = await list_repos_for_args(args)
    owner = await default_owner()
    await run_parallel(
        repos,
        make_worker(owner, args.dry_run),
        verbose=args.verbose,
        dry_run=args.dry_run,
    )
    return 0


async def _merge_settings_sync(args: argparse.Namespace) -> int:
    return await _run_worker_sync(args, make_merge_settings_worker)


async def _squash_title_sync(args: argparse.Namespace) -> int:
    return await _run_worker_sync(args, make_squash_title_worker)


async def cmd_merge_sync(args: argparse.Namespace) -> int:
    await _merge_settings_sync(args)
    return await _squash_title_sync(args)


# ---------------------------------------------------------------------------
# features sync
#
# Turns the repo-page features (issues, wiki, projects, discussions) on or
# off per config/features.yaml: a `"*"` entry for the fleet plus optional
# per-repo overrides. Only keys the config names are touched. The sidebar
# toggles for Releases/Packages/Deployments have no API and aren't managed.
# ---------------------------------------------------------------------------


async def _repo_features(owner: str, name: str) -> dict[str, bool]:
    data = await api_json("GET", f"/repos/{owner}/{name}")
    return {key: data[f"has_{key}"] for key in lib.FEATURE_KEYS}


def make_features_worker(owner: str, dry_run: bool):
    async def worker(repo: Repo) -> RepoResult:
        desired = lib.repo_features(repo.name)

        def drift(current: dict) -> dict[str, bool]:
            return {k: v for k, v in desired.items() if current[k] != v}

        def plan_result(current: dict) -> RepoResult:
            todo = drift(current)
            status = classify_status(at_target=True, changed=bool(todo))
            detail = (
                "would set: " + ", ".join(f"{k}={v}" for k, v in todo.items())
                if todo
                else str(current)
            )
            return RepoResult(repo, result_line(repo.name, detail, status), status)

        async def apply_result(before: dict) -> RepoResult:
            todo = drift(before)
            if not todo:
                status = classify_status(at_target=True, changed=False)
                return RepoResult(
                    repo, result_line(repo.name, str(before), status), status
                )
            await api_json(
                "PATCH",
                f"/repos/{owner}/{repo.name}",
                json={f"has_{k}": v for k, v in todo.items()},
            )
            after = await _repo_features(owner, repo.name)
            status = classify_status(at_target=not drift(after), changed=True)
            detail = str(after) if before == after else f"{before} -> {after}"
            return RepoResult(repo, result_line(repo.name, detail, status), status)

        return await run_reconcile(
            dry_run=dry_run,
            fetch=lambda: _repo_features(owner, repo.name),
            plan_result=plan_result,
            apply_result=apply_result,
        )

    return worker


async def _features_sync(args: argparse.Namespace) -> int:
    return await _run_worker_sync(args, make_features_worker)


# ---------------------------------------------------------------------------
# security sync
#
# Enables free, native GitHub security features:
#   - Dependabot vulnerability alerts -- works on every repo, no plan gate
#   - Dependabot security updates are turned OFF (their PRs are unwanted;
#     Renovate maintains dependencies), through their own endpoint so a
#     private repo's rejected secret-scanning request can't block it
#   - secret scanning and secret scanning push protection -- public repos
#     only; private repos need GitHub Advanced Security, a paid add-on this
#     account's plan doesn't include
#   - private vulnerability reporting -- same public-repo-only gate
#   - CodeQL code scanning default setup -- same public-repo-only gate, and
#     also unavailable on repos with no CodeQL-supported language
#
# Repos where a feature is unavailable are reported, not treated as a
# failure -- same approach as branch-protection's private-repo handling.
# ---------------------------------------------------------------------------


def security_summarize(
    repo_json: dict,
    *,
    vuln_alerts_enabled: bool,
    pvr_json: dict | None,
    codeql_json: dict | None,
) -> dict:
    sec = repo_json.get("security_and_analysis") or {}
    features = {
        "vuln_alerts": (vuln_alerts_enabled, True),
        "dependabot_updates_off": (
            (sec.get("dependabot_security_updates") or {}).get("status") != "enabled",
            True,
        ),
        "secret_scanning": (
            (sec.get("secret_scanning") or {}).get("status") == "enabled",
            sec.get("secret_scanning") is not None,
        ),
        "push_protection": (
            (sec.get("secret_scanning_push_protection") or {}).get("status")
            == "enabled",
            sec.get("secret_scanning_push_protection") is not None,
        ),
        "private_vuln_reporting": (
            (pvr_json or {}).get("enabled") is True,
            pvr_json is not None,
        ),
        "code_scanning": (
            (codeql_json or {}).get("state") == "configured",
            codeql_json is not None,
        ),
    }
    return partition_fields(features)


def security_dry_run_line(name: str, summary: dict, status: Status) -> str:
    would_enable, unavailable = summary["would_enable"], summary["unavailable"]
    detail = (
        "enabled" if not would_enable else f"would enable: {', '.join(would_enable)}"
    )
    return result_line(name, detail + unavailable_suffix(unavailable), status)


async def _fetch_security_state(
    owner: str, name: str
) -> tuple[dict, bool, dict | None, dict | None]:
    repo_json = await api_json("GET", f"/repos/{owner}/{name}")

    # 204 = enabled, 404 = disabled -- GitHub's documented shape for this
    # endpoint, not an error either way.
    vuln_response = await api_raw("GET", f"/repos/{owner}/{name}/vulnerability-alerts")
    if vuln_response.status_code not in (204, 404):
        raise GhError(
            error_message(vuln_response), status_code=vuln_response.status_code
        )
    vuln_alerts_enabled = vuln_response.status_code == 204

    # 200 = available (body has "enabled"), 404 = not available on this plan.
    pvr_response = await api_raw(
        "GET", f"/repos/{owner}/{name}/private-vulnerability-reporting"
    )
    if pvr_response.status_code not in (200, 404):
        raise GhError(error_message(pvr_response), status_code=pvr_response.status_code)
    pvr_json = pvr_response.json() if pvr_response.status_code == 200 else None

    # 200 = available (body has "state"), 404/403 = not available on this
    # plan or repo (no Advanced Security, GHES, or no supported language).
    codeql_response = await api_raw(
        "GET", f"/repos/{owner}/{name}/code-scanning/default-setup"
    )
    if codeql_response.status_code not in (200, 403, 404):
        raise GhError(
            error_message(codeql_response), status_code=codeql_response.status_code
        )
    codeql_json = codeql_response.json() if codeql_response.status_code == 200 else None

    return repo_json, vuln_alerts_enabled, pvr_json, codeql_json


def make_security_features_worker(owner: str, dry_run: bool):
    async def worker(repo: Repo) -> RepoResult:
        async def fetch() -> dict:
            (
                repo_json,
                vuln_alerts_enabled,
                pvr_json,
                codeql_json,
            ) = await _fetch_security_state(owner, repo.name)
            return security_summarize(
                repo_json,
                vuln_alerts_enabled=vuln_alerts_enabled,
                pvr_json=pvr_json,
                codeql_json=codeql_json,
            )

        def plan_result(before_summary: dict) -> RepoResult:
            status = summary_status(before_summary)
            return RepoResult(
                repo, security_dry_run_line(repo.name, before_summary, status), status
            )

        async def apply_result(before_summary: dict) -> RepoResult:
            await api_json("PUT", f"/repos/{owner}/{repo.name}/vulnerability-alerts")

            unavailable = []

            # 422 = one or more of these fields isn't available on this plan
            # (GitHub Advanced Security is required for private repos).
            security_response = await api_raw(
                "PATCH",
                f"/repos/{owner}/{repo.name}",
                json={
                    "security_and_analysis": {
                        "secret_scanning": {"status": "enabled"},
                        "secret_scanning_push_protection": {"status": "enabled"},
                    }
                },
            )
            if security_response.status_code == 422:
                unavailable.append("secret scanning")
            elif not security_response.is_success:
                raise GhError(
                    error_message(security_response),
                    status_code=security_response.status_code,
                )

            # 204 = disabled; 404 = alerts are off, so security updates are too.
            dependabot_response = await api_raw(
                "DELETE", f"/repos/{owner}/{repo.name}/automated-security-fixes"
            )
            if dependabot_response.status_code != 404 and not (
                dependabot_response.is_success
            ):
                raise GhError(
                    error_message(dependabot_response),
                    status_code=dependabot_response.status_code,
                )

            # 404 = not available on this plan.
            pvr_response = await api_raw(
                "PUT", f"/repos/{owner}/{repo.name}/private-vulnerability-reporting"
            )
            if pvr_response.status_code == 404:
                unavailable.append("private vulnerability reporting")
            elif not pvr_response.is_success:
                raise GhError(
                    error_message(pvr_response), status_code=pvr_response.status_code
                )

            # 403/404 = not available on this plan or repo; 422 = no
            # CodeQL-supported language detected in the repo.
            codeql_response = await api_raw(
                "PATCH",
                f"/repos/{owner}/{repo.name}/code-scanning/default-setup",
                json={"state": "configured"},
            )
            if codeql_response.status_code in (403, 404, 422):
                unavailable.append("code scanning")
            elif not codeql_response.is_success:
                raise GhError(
                    error_message(codeql_response),
                    status_code=codeql_response.status_code,
                )

            status = classify_status(
                at_target=not unavailable,
                changed=bool(before_summary["would_enable"]),
            )
            detail = "enabled" + unavailable_suffix(unavailable)
            tag = Tag.UNAVAILABLE if unavailable else None
            return RepoResult(
                repo, result_line(repo.name, detail, status), status, tag=tag
            )

        return await run_reconcile(
            dry_run=dry_run,
            fetch=fetch,
            plan_result=plan_result,
            apply_result=apply_result,
        )

    return worker


async def cmd_security_sync(args: argparse.Namespace) -> int:
    repos = await list_repos_for_args(args)
    results = await run_parallel(
        repos,
        make_security_features_worker(await default_owner(), args.dry_run),
        verbose=args.verbose,
        dry_run=args.dry_run,
    )

    if args.dry_run:
        return 0

    unavailable = sorted(r.repo.name for r in results if r.tag == Tag.UNAVAILABLE)
    print()
    print("Summary:")
    print(
        f"  Repos with unavailable features (private, needs GitHub Advanced Security): {' '.join(unavailable) or 'none'}"
    )
    return 0


def _tagged(results: list[RepoResult], tag: protection.Tag) -> list[str]:
    return sorted(r.repo.name for r in results if r.tag == tag)


async def cmd_protection_sync(args: argparse.Namespace) -> int:
    owner = await default_owner()
    exclude = default_branch_protection_exclude()
    repos = await list_repos_for_args(args, extra_skip=exclude)
    audits: dict[str, audit.RepoAudit] = {}
    results = await run_parallel(
        repos,
        protection.make_branch_protection_worker(
            owner,
            args.dry_run,
            clear_stale_checks=getattr(args, "clear_stale_checks", False),
            adopt_renamed_checks=getattr(args, "adopt_renamed_checks", False),
            audit=audits,
            ignored_checks=default_required_check_ignore(),
        ),
        verbose=args.verbose,
        dry_run=args.dry_run,
    )

    # Being excluded only keeps the apply loop above from touching a repo --
    # it says nothing about protection already in place, which must be
    # actively removed or it lingers forever. Only within the requested
    # scope (explicit repo args, minus an explicit --skip) so a scoped run
    # doesn't reach outside what was asked for.
    only = set(args.repos) or None
    unprotect_names = exclude - (as_set(args.skip) or set())
    if only is not None:
        unprotect_names &= only
    unprotect_results = []
    if unprotect_names:
        excluded_repos = await list_repos(owner, only=unprotect_names)
        unprotect_results = await run_parallel(
            excluded_repos,
            protection.make_branch_unprotect_worker(owner, args.dry_run),
            verbose=args.verbose,
            dry_run=args.dry_run,
        )

    Tag = protection.Tag
    summary = []
    if attention := _tagged(results, Tag.ATTENTION):
        summary.append(f"Needs manual attention: {' '.join(attention)}")
    if renames := _tagged(results, Tag.RENAME_CANDIDATE):
        summary.append(f"Candidates for --adopt-renamed-checks: {' '.join(renames)}")
    if removed := _tagged(unprotect_results, Tag.UNPROTECTED):
        verb = "Would remove" if args.dry_run else "Removed"
        summary.append(f"{verb} protection (excluded): {' '.join(removed)}")
    summary.extend(audit.summary_lines(audits))
    if summary:
        print()
        print("Summary:")
        for line in summary:
            print(f"  {line}")
    return 0


# ---------------------------------------------------------------------------
# pages sync
#
# Sets each repo's GitHub Pages custom domain from pages-domains.yaml -- the
# single source of truth, also consumed by the OpenTofu config that
# generates the matching CNAME/verification DNS records. Unlike the other
# commands, this doesn't apply the same setting account-wide: only repos
# listed in the mapping are touched. The repo's homepage URL is also pointed
# at https://<domain> so the "website" link tracks the custom domain.
#
# https_enforced is only ever turned on, never off, and only once GitHub
# reports the domain's certificate as "approved" -- that requires the CNAME
# DNS record to already resolve, so a freshly-set cname always needs a later
# rerun to pick up https_enforced once the cert catches up.
# ---------------------------------------------------------------------------


async def _pages_config(owner: str, name: str) -> dict:
    config = await _fetch_pages_config(owner, name)
    if config is None:
        raise GhError(
            f"Pages is not enabled on {owner}/{name} "
            "(it is mapped in config/pages-domains.yaml)",
            status_code=404,
        )
    return config


def pages_domain_https_ready(pages_json: dict) -> bool:
    return (pages_json.get("https_certificate") or {}).get("state") == "approved"


def pages_domain_up_to_date(pages_json: dict, domain: str) -> bool:
    return (
        pages_json.get("cname") == domain and pages_json.get("https_enforced") is True
    )


def pages_homepage_url(domain: str) -> str:
    return f"https://{domain}"


def pages_domain_dry_run_line(
    name: str,
    pages_json: dict,
    domain: str,
    status: Status,
    homepage_ok: bool = True,
) -> str:
    cname_ok = pages_json.get("cname") == domain
    https_ok = pages_json.get("https_enforced") is True
    if cname_ok and https_ok:
        detail = f"cname={domain}, https enforced"
    elif not cname_ok:
        detail = f"would set cname -> {domain}"
    elif pages_domain_https_ready(pages_json):
        detail = f"cname={domain}; would enable https_enforced"
    else:
        detail = f"cname={domain}; https cert pending"
    if not homepage_ok:
        detail += f"; would set homepage -> {pages_homepage_url(domain)}"
    return result_line(name, detail, status)


def pages_domain_apply_line(
    name: str,
    before: dict,
    after: dict,
    domain: str,
    status: Status,
    homepage_changed: bool = False,
    enabled: bool = False,
) -> str:
    cname_changed = before.get("cname") != after.get("cname")
    https_changed = before.get("https_enforced") != after.get("https_enforced")
    if not (cname_changed or https_changed or homepage_changed or enabled):
        detail = (
            f"cname={domain}, https enforced"
            if after.get("https_enforced")
            else f"cname={domain}; https cert pending"
        )
        return result_line(name, detail, status)
    parts = ["enabled Pages (workflow)"] if enabled else []
    if cname_changed:
        parts.append(f"cname -> {domain}")
    if https_changed:
        parts.append("https_enforced -> true")
    if homepage_changed:
        parts.append(f"homepage -> {pages_homepage_url(domain)}")
    return result_line(name, ", ".join(parts), status)


def make_pages_domain_worker(
    owner: str, dry_run: bool, domains: dict[str, str], enable: bool = False
):
    async def worker(repo: Repo) -> RepoResult:
        domain = domains[repo.name]
        homepage_ok = repo.homepage == pages_homepage_url(domain)

        async def fetch() -> dict | None:
            try:
                return await _pages_config(owner, repo.name)
            except GhError as exc:
                if enable and exc.status_code == 404:
                    return None
                raise

        def plan_result(current: dict | None) -> RepoResult:
            if current is None:
                detail = f"would enable Pages (workflow), set cname -> {domain}"
                return RepoResult(
                    repo,
                    result_line(repo.name, detail, Status.LIMITED),
                    Status.LIMITED,
                )
            would_change = (
                current.get("cname") != domain
                or not homepage_ok
                or (
                    pages_domain_https_ready(current)
                    and current.get("https_enforced") is not True
                )
            )
            status = classify_status(
                at_target=pages_domain_up_to_date(current, domain) and homepage_ok,
                changed=would_change,
            )
            return RepoResult(
                repo,
                pages_domain_dry_run_line(
                    repo.name, current, domain, status, homepage_ok
                ),
                status,
            )

        async def apply_result(before: dict | None) -> RepoResult:
            enabled = before is None
            if before is None:
                await api_json(
                    "POST",
                    f"/repos/{owner}/{repo.name}/pages",
                    json={"build_type": "workflow"},
                )
                before = await _pages_config(owner, repo.name)

            payload: dict = {}
            if before.get("cname") != domain:
                payload["cname"] = domain
            elif (
                pages_domain_https_ready(before)
                and before.get("https_enforced") is not True
            ):
                payload["https_enforced"] = True

            if payload:
                await api_json("PUT", f"/repos/{owner}/{repo.name}/pages", json=payload)
                after = await _pages_config(owner, repo.name)
            else:
                after = before

            if not homepage_ok:
                await api_json(
                    "PATCH",
                    f"/repos/{owner}/{repo.name}",
                    json={"homepage": pages_homepage_url(domain)},
                )

            status = classify_status(
                at_target=pages_domain_up_to_date(after, domain),
                changed=enabled or before != after or not homepage_ok,
            )
            return RepoResult(
                repo,
                pages_domain_apply_line(
                    repo.name,
                    before,
                    after,
                    domain,
                    status,
                    homepage_changed=not homepage_ok,
                    enabled=enabled,
                ),
                status,
            )

        return await run_reconcile(
            dry_run=dry_run,
            fetch=fetch,
            plan_result=plan_result,
            apply_result=apply_result,
        )

    return worker


async def cmd_pages_sync(args: argparse.Namespace) -> int:
    domains = lib.default_pages_domains()
    only = set(args.repos)
    if only:
        unknown = only - set(domains)
        if unknown:
            print(
                f"error: not in config/pages-domains.yaml: {', '.join(sorted(unknown))}",
                file=sys.stderr,
            )
            return 1
    else:
        only = set(domains)

    repos = await list_repos(await default_owner(), only=only, skip=as_set(args.skip))
    await run_parallel(
        repos,
        make_pages_domain_worker(
            await default_owner(),
            args.dry_run,
            domains,
            enable=getattr(args, "enable", False),
        ),
        verbose=args.verbose,
        dry_run=args.dry_run,
    )
    return 0


# ---------------------------------------------------------------------------
# pages disable / unset-url
#
# The teardown counterparts to pages sync, for a repo that has been dropped
# from pages-domains.yaml. Both require explicit repo names and refuse repos
# still in the mapping, since pages sync would just put them back.
# ---------------------------------------------------------------------------


def make_pages_disable_worker(owner: str, dry_run: bool):
    async def worker(repo: Repo) -> RepoResult:
        async def apply_result(current: dict | None) -> RepoResult:
            if current is not None:
                await api_json("DELETE", f"/repos/{owner}/{repo.name}/pages")
            return _pages_disable_result(repo, current)

        return await run_reconcile(
            dry_run=dry_run,
            fetch=lambda: _fetch_pages_config(owner, repo.name),
            plan_result=lambda current: _pages_disable_result(
                repo, current, planned=True
            ),
            apply_result=apply_result,
        )

    return worker


def _pages_disable_result(
    repo: Repo, current: dict | None, planned: bool = False
) -> RepoResult:
    if current is None:
        return RepoResult(
            repo,
            result_line(repo.name, "Pages already disabled", Status.UNCHANGED),
            Status.UNCHANGED,
        )
    verb = "would disable" if planned else "disabled"
    detail = f"{verb} Pages (cname={current.get('cname')})"
    return RepoResult(repo, result_line(repo.name, detail, Status.OK), Status.OK)


def make_pages_unset_url_worker(owner: str, dry_run: bool):
    async def worker(repo: Repo) -> RepoResult:
        if not repo.homepage:
            return RepoResult(
                repo,
                result_line(repo.name, "no homepage set", Status.UNCHANGED),
                Status.UNCHANGED,
            )
        if dry_run:
            detail = f"would clear homepage {repo.homepage}"
        else:
            await api_json(
                "PATCH", f"/repos/{owner}/{repo.name}", json={"homepage": ""}
            )
            detail = f"cleared homepage {repo.homepage}"
        return RepoResult(repo, result_line(repo.name, detail, Status.OK), Status.OK)

    return worker


async def _pages_teardown_repos(args: argparse.Namespace) -> list[Repo] | None:
    if not args.repos:
        print("error: name at least one repo", file=sys.stderr)
        return None
    mapped = set(args.repos) & set(lib.default_pages_domains())
    if mapped:
        print(
            "error: still in config/pages-domains.yaml, remove it there first: "
            f"{', '.join(sorted(mapped))}",
            file=sys.stderr,
        )
        return None
    return await list_repos_for_args(args)


async def _run_pages_teardown(args: argparse.Namespace, make_worker) -> int:
    repos = await _pages_teardown_repos(args)
    if repos is None:
        return 1
    await run_parallel(
        repos,
        make_worker(await default_owner(), args.dry_run),
        verbose=args.verbose,
        dry_run=args.dry_run,
    )
    return 0


async def cmd_pages_disable(args: argparse.Namespace) -> int:
    return await _run_pages_teardown(args, make_pages_disable_worker)


async def cmd_pages_unset_url(args: argparse.Namespace) -> int:
    return await _run_pages_teardown(args, make_pages_unset_url_worker)


# ---------------------------------------------------------------------------
# pages status
#
# Read-only survey of which repos have GitHub Pages enabled and what custom
# domain (if any) they're currently serving -- lets config/pages-domains.yaml
# be checked for repos that have Pages on but aren't mapped yet.
# ---------------------------------------------------------------------------


async def _fetch_pages_config(owner: str, name: str) -> dict | None:
    response = await api_raw("GET", f"/repos/{owner}/{name}/pages")
    if response.status_code == 404:
        return None
    if not response.is_success:
        raise GhError(error_message(response), status_code=response.status_code)
    return response.json()


async def _pages_enabled_repos(repos: list[Repo]) -> list[tuple[Repo, dict]]:
    """Fetches every repo's Pages config concurrently and returns the ones
    with Pages enabled, sorted by name.
    """
    sem = asyncio.Semaphore(DEFAULT_JOBS)

    async def fetch_one(repo: Repo) -> tuple[Repo, dict | None]:
        async with sem:
            return repo, await _fetch_pages_config(await default_owner(), repo.name)

    with lib.progress_bar() as progress:
        task = progress.add_task("Fetching Pages config...", total=len(repos))

        async def fetch_and_advance(repo: Repo) -> tuple[Repo, dict | None]:
            result = await fetch_one(repo)
            progress.advance(task)
            return result

        results = await asyncio.gather(*(fetch_and_advance(repo) for repo in repos))

    enabled: list[tuple[Repo, dict]] = [
        (repo, config) for repo, config in results if config is not None
    ]
    enabled.sort(key=lambda item: item[0].name)
    return enabled


async def cmd_pages_status(args: argparse.Namespace) -> int:
    with lib.progress_bar(transient=True) as progress:
        progress.add_task("Fetching repos...", total=None)
        repos = await list_repos_for_args(args)

    enabled = await _pages_enabled_repos(repos)
    domains = lib.default_pages_domains()

    table = Table()
    table.add_column("NAME")
    table.add_column("URL", overflow="fold")
    table.add_column("HTTPS")
    table.add_column("MAPPED")
    table.add_column("HOMEPAGE", overflow="fold")
    for repo, config in enabled:
        https = (
            "enforced"
            if config.get("https_enforced")
            else (config.get("https_certificate") or {}).get("state", "n/a")
        )
        table.add_row(
            repo.name,
            config.get("html_url") or "(unknown)",
            https,
            "yes" if repo.name in domains else "no",
            repo.homepage or "(none)",
        )
    lib.console.print(table)

    missing = sorted(repo.name for repo, _config in enabled if repo.name not in domains)
    if missing:
        print()
        print(
            f"Pages enabled but not in config/pages-domains.yaml: {' '.join(missing)}"
        )

    return 0


# ---------------------------------------------------------------------------
# pages config
#
# Prints config/pages-domains.yaml-formatted entries to stdout for a base
# domain -- `<repo> -> <repo>.<domain>`, dots in the repo name replaced with
# dashes since a raw dot would split a hostname across two DNS labels
# instead of one. Given repo names, generates for exactly those repos (no
# API calls). With none, auto-discovers repos with Pages enabled but
# missing from config/pages-domains.yaml -- the same set `pages status`
# flags -- and suggests entries for those.
# ---------------------------------------------------------------------------


def pages_domain_suggest(repo_name: str, domain: str) -> str:
    return f"{repo_name.replace('.', '-')}.{domain}"


async def cmd_pages_config(args: argparse.Namespace) -> int:
    only = set(args.repos)
    if only:
        names = sorted(only)
    else:
        repos = await list_repos(
            await default_owner(), only=None, skip=as_set(args.skip)
        )
        enabled = await _pages_enabled_repos(repos)
        domains = lib.default_pages_domains()
        names = sorted(
            repo.name for repo, _config in enabled if repo.name not in domains
        )

    for name in names:
        print(f"{name}: {pages_domain_suggest(name, args.domain)}")

    return 0


# ---------------------------------------------------------------------------
# secrets sync / variables sync
#
# Pushes GitHub Actions secrets / variables to their configured repos via
# GitHub's REST API (lib.set_repo_secret -- PyNaCl-encrypted for the repo's
# public key -- / lib.set_repo_variable), consistent with every other
# mutating command here rather than shelling out to `gh secret set`.
#
# Secrets: name, target repos and values all live in the sops-encrypted
# config/secrets.enc.yaml as `NAME: [{repos: [...], value: str}, ...]` --
# one binding per distinct value, so a name that needs a different token in
# two repos is two bindings. The whole file is decrypted once via `sops -d`
# at the start of the run (dry-run included, since the mapping is encrypted
# too). Variables: values in config/variables.enc.yaml, but the
# non-sensitive name -> repos map stays plaintext in config/variables.yaml.
#
# There's no "unchanged" detection -- GitHub never returns a secret's value,
# and a variable set is unconditional anyway -- so every apply run sets, and
# dry-run just reports what would be set.
#
# A name maps to many repos and a repo can receive many names, so this loops
# per-name (its own list_repos + run_parallel each) -- the same non-aborting
# chaining cmd_sync does across sub-commands, so one name's failure doesn't
# stop the next.
# ---------------------------------------------------------------------------


def _echo_name_line(text: str, *, file=None) -> None:
    """print() for this section's status lines. `text` is built only from
    secret/variable *names* (config-map keys) and repo names -- never a
    value from an encrypted store. CodeQL's clear-text-logging query still
    taints everything downstream of a "secret"-named symbol and flags this
    `print`; the finding is a false positive, funnelled through one helper
    so it's a single alert to dismiss rather than one per call site.
    """
    print(text, file=file)


def secrets_sync_line(secret_name: str, repo_name: str, *, dry_run: bool) -> str:
    detail = f"would set {secret_name}" if dry_run else f"set {secret_name}"
    return result_line(repo_name, detail, Status.OK)


def variables_sync_line(name: str, repo_name: str, *, dry_run: bool) -> str:
    detail = f"would set {name}" if dry_run else f"set {name}"
    return result_line(repo_name, detail, Status.OK)


def make_secrets_sync_worker(owner: str, dry_run: bool, secret_name: str, value: str):
    async def worker(repo: Repo) -> RepoResult:
        line = secrets_sync_line(secret_name, repo.name, dry_run=dry_run)
        if not dry_run:
            await lib.set_repo_secret(owner, repo.name, secret_name, value)
        return RepoResult(repo, line, Status.OK)

    return worker


def make_variables_sync_worker(owner: str, dry_run: bool, name: str, value: str):
    async def worker(repo: Repo) -> RepoResult:
        line = variables_sync_line(name, repo.name, dry_run=dry_run)
        if not dry_run:
            await lib.set_repo_variable(owner, repo.name, name, value)
        return RepoResult(repo, line, Status.OK)

    return worker


def _scoped(repos, only: set[str] | None, skip: set[str] | None) -> set[str]:
    scoped = set(repos)
    if only:
        scoped &= only
    if skip:
        scoped -= skip
    return scoped


async def _run_name_sync(
    args: argparse.Namespace,
    *,
    names: set[str],
    bindings_for: Callable[
        [str, set[str], set[str] | None], list[tuple[set[str], str]]
    ],
    has_value: Callable[[str, str], bool],
    missing_value_error: Callable[[str, set[str]], str],
    make_worker,
    owner: str,
) -> int:
    only = set(args.repos)
    skip = as_set(args.skip)
    failed = False
    for name in sorted(names):
        bindings = bindings_for(name, only, skip)
        if not any(repos for repos, _ in bindings):
            _echo_name_line(f"== {name} == (no matching repos, skipping)")
            continue

        _echo_name_line(f"== {name} ==")
        for target_repos, value in bindings:
            if not target_repos:
                continue
            if not args.dry_run and not has_value(name, value):
                _echo_name_line(
                    missing_value_error(name, target_repos), file=sys.stderr
                )
                failed = True
                continue
            repos = await list_repos(owner, only=target_repos)
            try:
                await run_parallel(
                    repos,
                    make_worker(owner, args.dry_run, name, value),
                    verbose=args.verbose,
                    dry_run=args.dry_run,
                )
            except GhError as exc:
                print(exc, file=sys.stderr)
                failed = True

    return 1 if failed else 0


async def cmd_secrets_sync(args: argparse.Namespace) -> int:
    try:
        config = lib.load_secrets()
    except GhError as exc:
        print(exc, file=sys.stderr)
        return 1

    names = as_set(args.secret)
    if names:
        unknown = names - set(config)
        if unknown:
            print(
                f"error: not in config/secrets.enc.yaml: {', '.join(sorted(unknown))}",
                file=sys.stderr,
            )
            return 1
    else:
        names = set(config)

    def bindings_for(name, only, skip):
        return [
            (_scoped(binding["repos"], only, skip), binding["value"])
            for binding in config[name]
        ]

    def missing_value_error(name, target_repos):
        return (
            f"error: {name!r} has an empty value for "
            f"{', '.join(sorted(target_repos))} in config/secrets.enc.yaml"
        )

    return await _run_name_sync(
        args,
        names=names,
        bindings_for=bindings_for,
        has_value=lambda name, value: bool(value),
        missing_value_error=missing_value_error,
        make_worker=make_secrets_sync_worker,
        owner=await default_owner(),
    )


async def cmd_variables_sync(args: argparse.Namespace) -> int:
    config = lib.default_variables()
    names = as_set(args.variable)
    if names:
        unknown = names - set(config)
        if unknown:
            print(
                f"error: not in config/variables.yaml: {', '.join(sorted(unknown))}",
                file=sys.stderr,
            )
            return 1
    else:
        names = set(config)

    values = lib.decrypt_variables() if not args.dry_run else {}

    def bindings_for(name, only, skip):
        return [(_scoped(config[name], only, skip), values.get(name, ""))]

    return await _run_name_sync(
        args,
        names=names,
        bindings_for=bindings_for,
        has_value=lambda name, _value: name in values,
        missing_value_error=lambda name, _target_repos: (
            f"error: {name!r} has no value in config/variables.enc.yaml"
        ),
        make_worker=make_variables_sync_worker,
        owner=await default_owner(),
    )


# ---------------------------------------------------------------------------
# secrets edit / variables edit
#
# Opens config/{secrets,variables}.enc.yaml in `sops` for interactive
# editing (decrypts to $EDITOR, re-encrypts on save).
#
# secrets edit works on the single self-contained file: it seeds a one-entry
# example when the file is missing, then re-parses on save to surface a
# malformed binding. variables edit still seeds from config/variables.yaml's
# names and warns about drift against it (a configured name with no value, a
# leftover value for a removed name).
# ---------------------------------------------------------------------------

_SECRETS_EDIT_EXAMPLE = (
    "EXAMPLE_SECRET:\n  - repos: [some-repo, other-repo]\n    value: ''\n"
)


def secrets_edit_template(names: set[str]) -> str:
    return yaml.safe_dump({name: "" for name in sorted(names)}, sort_keys=False)


async def _run_config_edit(
    *, names: set[str], enc_file, init_fn, edit_fn, decrypt_fn, plaintext_file: str
) -> int:
    if not names:
        print(f"error: nothing configured in {plaintext_file}", file=sys.stderr)
        return 1

    if not enc_file.exists():
        print(f"creating {enc_file.name}...")
        init_fn(secrets_edit_template(names))

    if edit_fn() != 0:
        print(
            "error: sops exited with a nonzero status; changes may not be saved",
            file=sys.stderr,
        )
        return 1

    values = decrypt_fn()
    missing = names - set(values)
    stale = set(values) - names
    if missing:
        print(
            f"warning: no value set for: {', '.join(sorted(missing))}", file=sys.stderr
        )
    if stale:
        print(
            f"warning: not in {plaintext_file} (stale?): {', '.join(sorted(stale))}",
            file=sys.stderr,
        )
    return 0


async def cmd_secrets_edit(args: argparse.Namespace) -> int:
    if not lib.SECRETS_ENC_FILE.exists():
        print(f"creating {lib.SECRETS_ENC_FILE.name}...")
        lib.init_secrets_file(_SECRETS_EDIT_EXAMPLE)

    if lib.edit_secrets_file() != 0:
        print(
            "error: sops exited with a nonzero status; changes may not be saved",
            file=sys.stderr,
        )
        return 1

    try:
        lib.load_secrets()
    except GhError as exc:
        print(f"warning: {exc}", file=sys.stderr)
    return 0


async def cmd_variables_edit(args: argparse.Namespace) -> int:
    return await _run_config_edit(
        names=set(lib.default_variables()),
        enc_file=lib.VARIABLES_ENC_FILE,
        init_fn=lib.init_variables_file,
        edit_fn=lib.edit_variables_file,
        decrypt_fn=lib.decrypt_variables,
        plaintext_file="config/variables.yaml",
    )


# ---------------------------------------------------------------------------
# config bootstrap
#
# First-run helper for a repo: reads which secrets.* / vars.* its workflows
# reference (straight off GitHub, so the list can't drift from the workflow
# file), binds the repo in config/secrets.enc.yaml + config/variables.yaml,
# and prompts for any value not already stored. Prints the `secrets sync` /
# `variables sync` commands to run next -- populating config and applying it
# stay separate, like `secrets edit` vs `secrets sync`.
#
# A new secret name gets a fresh single binding with the prompted value; an
# existing name adds the repo to its first binding (sharing that value). A
# repo needing its own value for an already-bound name is a `secrets edit`
# job, not a bootstrap one.
# ---------------------------------------------------------------------------

CONFIG_MAP_HEADER = (
    "# Variable name -> target repo list. Values live sops-encrypted in\n"
    "# variables.enc.yaml. Managed by `repo_admin.py config bootstrap`;\n"
    "# hand-edits welcome.\n"
)


def _add_repo_to_config_map(path, names: set[str], repo: str) -> list[str]:
    """Ensures every name in `path`'s `name -> {repos: [...]}` map lists
    `repo`, writing the file back only if anything changed. Returns the
    names whose repo list gained `repo`.
    """
    raw = (yaml.safe_load(path.read_text()) if path.exists() else None) or {}
    added: list[str] = []
    for name in sorted(names):
        repos = raw.setdefault(name, {}).setdefault("repos", [])
        if repo not in repos:
            repos.append(repo)
            repos.sort()
            added.append(name)
    if added:
        path.write_text(CONFIG_MAP_HEADER + yaml.safe_dump(raw, sort_keys=True))
    return added


def _prompt_missing_values(enc_file, names: set[str], decrypt_fn, prompt) -> list[str]:
    """Prompts (via `prompt`) for each name not already in `enc_file`, and
    writes the merged set back through sops. Blank input is skipped.
    Returns the names that got a value.
    """
    current = decrypt_fn() if enc_file.exists() else {}
    merged = dict(current)
    got: list[str] = []
    for name in sorted(names):
        if name in current:
            _echo_name_line(f"  {name}: (already set, skipping)")
            continue
        value = prompt(f"  {name}: ")
        if value:
            merged[name] = value
            got.append(name)
    if got:
        lib.write_enc_file(enc_file, merged)
    return got


def _bootstrap_secret_bindings(names: set[str], repo: str, prompt) -> list[str]:
    """Binds `repo` under each secret name in config/secrets.enc.yaml,
    prompting (via `prompt`) for the value of any name not there yet, and
    re-encrypts if anything changed. Returns the names that gained `repo`.
    """
    current = lib.load_secrets() if lib.SECRETS_ENC_FILE.exists() else {}
    merged = {name: [dict(b) for b in bindings] for name, bindings in current.items()}
    added: list[str] = []
    for name in sorted(names):
        bindings = merged.setdefault(name, [])
        if any(repo in b["repos"] for b in bindings):
            _echo_name_line(f"  {name}: (already bound to {repo}, skipping)")
            continue
        if bindings:
            bindings[0]["repos"] = sorted({*bindings[0]["repos"], repo})
            _echo_name_line(f"  {name}: bound {repo} to the existing value")
        else:
            merged[name] = [{"repos": [repo], "value": prompt(f"  {name}: ")}]
        added.append(name)
    if added:
        lib.write_enc_file(lib.SECRETS_ENC_FILE, merged)
    return added


async def cmd_config_bootstrap(args: argparse.Namespace) -> int:
    owner = await default_owner()
    repo = args.repo

    texts = await lib.fetch_workflow_texts(owner, repo)
    if not texts:
        print(f"error: {owner}/{repo} has no .github/workflows/ files", file=sys.stderr)
        return 1

    secret_names, var_names = lib.workflow_config_names(texts)
    if not secret_names and not var_names:
        print(f"{repo}: workflows reference no secrets.* or vars.* -- nothing to do")
        return 0

    print(f"{repo} workflows reference:")
    _echo_name_line(f"  secrets:   {', '.join(sorted(secret_names)) or '(none)'}")
    _echo_name_line(f"  variables: {', '.join(sorted(var_names)) or '(none)'}")

    _add_repo_to_config_map(lib.VARIABLES_FILE, var_names, repo)

    if secret_names:
        print("\nsecret values (input hidden; Enter to keep/skip):")
        _bootstrap_secret_bindings(secret_names, repo, getpass)
    if var_names:
        print("\nvariable values (Enter to keep/skip):")
        _prompt_missing_values(
            lib.VARIABLES_ENC_FILE, var_names, lib.decrypt_variables, input
        )

    print("\nconfig updated. Apply it with:")
    if secret_names:
        print(f"  ./repo-admin.sh secrets sync {repo} --dry-run")
    if var_names:
        print(f"  ./repo-admin.sh variables sync {repo} --dry-run")
    return 0


# ---------------------------------------------------------------------------
# sync (meta)
# ---------------------------------------------------------------------------


async def cmd_sync(args: argparse.Namespace) -> int:
    """Runs merge, protection, security, then pages sync in that order
    (matching the README's ordering -- merge sync's PR-branch auto-update
    makes protection sync's auto-merge-friendly baseline behave as
    intended). merge sync's squash-title step is split out to run right
    after protection sync, since it keys off the `semantic-pr` required
    check that protection sync adds. One
    command failing doesn't stop the others, except an exhausted rate limit,
    which would fail them all; the exit code is nonzero if any of them failed.
    """
    failed = False
    for name, cmd in (
        ("merge sync", _merge_settings_sync),
        ("features sync", _features_sync),
        ("protection sync", cmd_protection_sync),
        ("squash title sync", _squash_title_sync),
        ("security sync", cmd_security_sync),
        ("pages sync", _cmd_pages_sync_mapped_only),
    ):
        print(f"== {name} ==")
        try:
            if await cmd(args) != 0:
                failed = True
        except GhRateLimitError as exc:
            print(exc, file=sys.stderr)
            return 1
        except GhError as exc:
            print(exc, file=sys.stderr)
            failed = True
    return 1 if failed else 0


async def _cmd_pages_sync_mapped_only(args: argparse.Namespace) -> int:
    """pages sync for the meta `sync`: repos named on the command line but
    absent from pages-domains.yaml are dropped rather than rejected, since
    they were named for the other syncs.
    """
    if not args.repos:
        return await cmd_pages_sync(args)
    mapped = [r for r in args.repos if r in lib.default_pages_domains()]
    if not mapped:
        return 0
    return await cmd_pages_sync(argparse.Namespace(**{**vars(args), "repos": mapped}))


# ---------------------------------------------------------------------------
# activity
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    resources = parser.add_subparsers(dest="resource", required=True)

    repo_scope = argparse.ArgumentParser(add_help=False)
    repo_scope.add_argument(
        "repos", nargs="*", metavar="REPO", help="repo names to target (default: all)"
    )
    repo_scope.add_argument(
        "-s", "--skip", help="comma-separated repo names to exclude"
    )

    mutating = argparse.ArgumentParser(add_help=False, parents=[repo_scope])
    mutating.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="show what would change, without changing anything",
    )
    mutating.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show unchanged repos too, not just changes",
    )

    def resource_verbs(name: str) -> argparse._SubParsersAction:
        return resources.add_parser(name).add_subparsers(dest="verb", required=True)

    resource_verbs("repos").add_parser("list", parents=[repo_scope]).set_defaults(
        func=cmd_repos_list
    )

    repo_scaffold = resource_verbs("repo").add_parser(
        "scaffold", help="render a new repo's baseline files from templates/"
    )
    scaffold.add_arguments(repo_scaffold)
    repo_scaffold.set_defaults(func=scaffold.run)
    resource_verbs("merge").add_parser("sync", parents=[mutating]).set_defaults(
        func=cmd_merge_sync
    )
    protection_sync = resource_verbs("protection").add_parser(
        "sync", parents=[mutating]
    )
    protection_sync.add_argument(
        "-c",
        "--clear-stale-checks",
        action="store_true",
        help=(
            "drop required status checks for a repo whose recent PRs yield no "
            "sampleable check runs (default: keep the existing ones)"
        ),
    )
    protection_sync.add_argument(
        "-a",
        "--adopt-renamed-checks",
        action="store_true",
        help=(
            "when a required check looks renamed on an open PR (e.g. "
            "'test / Tests' -> 'Tests'), adopt the sampled name instead of "
            "keeping the old one, even before the rename lands on the default "
            "branch (default: keep the old name until the base branch confirms)"
        ),
    )
    protection_sync.set_defaults(func=cmd_protection_sync)
    resource_verbs("security").add_parser("sync", parents=[mutating]).set_defaults(
        func=cmd_security_sync
    )
    resource_verbs("features").add_parser("sync", parents=[mutating]).set_defaults(
        func=_features_sync
    )
    resources.add_parser("sync", parents=[mutating]).set_defaults(func=cmd_sync)

    pages = resource_verbs("pages")
    pages.add_parser("status", parents=[repo_scope]).set_defaults(func=cmd_pages_status)
    pages_sync = pages.add_parser("sync", parents=[mutating])
    pages_sync.add_argument(
        "-e",
        "--enable",
        action="store_true",
        help=(
            "enable GitHub Pages (GitHub Actions build) on mapped repos that "
            "don't have it yet (default: report them as failed)"
        ),
    )
    pages_sync.set_defaults(func=cmd_pages_sync)
    pages.add_parser("disable", parents=[mutating]).set_defaults(func=cmd_pages_disable)
    pages.add_parser("unset-url", parents=[mutating]).set_defaults(
        func=cmd_pages_unset_url
    )
    pages_config_parser = pages.add_parser("config", parents=[repo_scope])
    pages_config_parser.add_argument(
        "-d", "--domain", required=True, help="base domain, e.g. larve.net"
    )
    pages_config_parser.set_defaults(func=cmd_pages_config)

    secrets = resource_verbs("secrets")
    secrets_sync_parser = secrets.add_parser("sync", parents=[mutating])
    secrets_sync_parser.add_argument(
        "-S",
        "--secret",
        help="comma-separated secret names to sync (default: all in "
        "config/secrets.enc.yaml)",
    )
    secrets_sync_parser.set_defaults(func=cmd_secrets_sync)
    secrets.add_parser("edit").set_defaults(func=cmd_secrets_edit)

    variables = resource_verbs("variables")
    variables_sync_parser = variables.add_parser("sync", parents=[mutating])
    variables_sync_parser.add_argument(
        "-V",
        "--variable",
        help="comma-separated variable names to sync (default: all in "
        "config/variables.yaml)",
    )
    variables_sync_parser.set_defaults(func=cmd_variables_sync)
    variables.add_parser("edit").set_defaults(func=cmd_variables_edit)

    config_bootstrap = resource_verbs("config").add_parser(
        "bootstrap",
        help="add a repo to config/{secrets,variables}.yaml from its workflow "
        "refs and prompt for values",
    )
    config_bootstrap.add_argument("repo", help="the repo to configure")
    config_bootstrap.set_defaults(func=cmd_config_bootstrap)

    activity_parser = resources.add_parser("activity")
    activity_parser.add_argument(
        "-w",
        "--window-months",
        type=int,
        default=12,
        help="how far back to fetch commits, in months (default 12)",
    )
    activity_parser.add_argument(
        "-H",
        "--half-life-days",
        type=float,
        default=30,
        help="decay half-life for the ranking score, in days (default 30)",
    )
    activity_parser.add_argument(
        "-l",
        "--limit",
        type=int,
        default=20,
        help="max repos to show per table, 0 for unlimited (default 20)",
    )
    activity_parser.set_defaults(func=activity.run)

    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    return lib.run_cli(args.func, args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
