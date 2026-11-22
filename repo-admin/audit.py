"""Static audit of a repo's workflows, reported at the end of `protection sync`.

It answers "can this repo release something from a commit whose checks did not
pass, and is the default branch red?" without changing anything. The inputs are
the parsed workflow documents and the required checks `protection sync` decided
on, so every rule here is a pure function of data and easy to test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_GATE_JOB = re.compile(r"(^|-)gate$")
_CI_GATE = "ci-gate"
_RELEASE_KEYS = {"release", "release-please", "tag"}
_RELEASE_USES = re.compile(r"/(spoon-)?release\.yml@")
_MANAGED_RUN_PATH = ".github/workflows/"


@dataclass
class RepoAudit:
    ungated: list[str] = field(default_factory=list)
    needs_gated: list[str] = field(default_factory=list)
    unlisted: list[str] = field(default_factory=list)
    gate_not_required: bool = False
    red: list[str] = field(default_factory=list)


def _jobs(doc: dict) -> dict[str, dict]:
    return {k: v for k, v in (doc.get("jobs") or {}).items() if isinstance(v, dict)}


def _needs(job: dict) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def _closure(jobs: dict[str, dict], key: str) -> set[str]:
    """Every job `key` waits on, directly or through other jobs."""
    seen: set[str] = set()
    stack = _needs(jobs.get(key, {}))
    while stack:
        need = stack.pop()
        if need in seen or need not in jobs:
            continue
        seen.add(need)
        stack.extend(_needs(jobs[need]))
    return seen


def _is_release(key: str, job: dict) -> bool:
    return (
        key in _RELEASE_KEYS
        or key.startswith("publish")
        or bool(_RELEASE_USES.search(str(job.get("uses", ""))))
    )


_OWN_TRIGGERS = {
    "push",
    "pull_request",
    "pull_request_target",
    "schedule",
    "workflow_dispatch",
    "workflow_run",
}


def _triggers(doc: dict) -> set[str]:
    on = doc.get("on", doc.get(True))  # YAML reads a bare `on:` key as True
    if isinstance(on, dict):
        return set(on)
    if isinstance(on, str):
        return {on}
    return set(on or [])


def _callable_only(doc: dict) -> bool:
    """A reusable workflow nothing triggers on its own: its caller gates it."""
    triggers = _triggers(doc)
    return "workflow_call" in triggers and not triggers & _OWN_TRIGGERS


def audit_workflows(docs: list[dict], required: list[str]) -> RepoAudit:
    report = RepoAudit()
    for doc in docs:
        if _callable_only(doc):
            continue
        jobs = _jobs(doc)
        for key, job in jobs.items():
            if not _is_release(key, job):
                continue
            needed = _closure(jobs, key)
            if any(_GATE_JOB.search(n) for n in needed):
                continue
            (report.needs_gated if needed else report.ungated).append(key)
        if _CI_GATE in jobs:
            if _CI_GATE not in required:
                report.gate_not_required = True
            behind = _closure(jobs, _CI_GATE)
            report.unlisted += [
                key
                for key in jobs
                if key != _CI_GATE
                and key not in behind
                and _CI_GATE not in _closure(jobs, key)
            ]
    report.ungated.sort()
    report.needs_gated.sort()
    report.unlisted.sort()
    return report


def red_workflows(runs: list[dict], active: set[int] | None = None) -> list[str]:
    """Workflows whose latest conclusive run on the default branch failed.

    `runs` is newest first, as the API returns it. Cancelled and skipped runs
    say nothing about the branch, GitHub-managed workflows (CodeQL default
    setup runs from a `dynamic/...` path) are not the repo's own, and a
    workflow whose file was deleted keeps its last runs forever, so `active`
    (the ids of workflows that still exist) drops those.
    """
    latest: dict[int, tuple[str, str]] = {}
    for run in runs:
        if not str(run.get("path", "")).startswith(_MANAGED_RUN_PATH):
            continue
        if active is not None and run["workflow_id"] not in active:
            continue
        if run.get("conclusion") not in ("success", "failure"):
            continue
        latest.setdefault(run["workflow_id"], (run["name"], run["conclusion"]))
    return sorted(
        name for name, conclusion in latest.values() if conclusion == "failure"
    )


def _repos_with_jobs(audits: dict[str, RepoAudit], attr: str) -> str:
    return ", ".join(
        f"{name} ({', '.join(getattr(a, attr))})"
        for name, a in sorted(audits.items())
        if getattr(a, attr)
    )


def summary_lines(audits: dict[str, RepoAudit]) -> list[str]:
    lines = []
    if text := _repos_with_jobs(audits, "ungated"):
        lines.append(f"Release not behind a gate: {text}")
    if text := _repos_with_jobs(audits, "needs_gated"):
        lines.append(f"Release gated only by needs on checks (no ci-gate): {text}")
    if names := ", ".join(n for n, a in sorted(audits.items()) if a.gate_not_required):
        lines.append(f"ci-gate exists but is not required: {names}")
    if text := _repos_with_jobs(audits, "unlisted"):
        lines.append(f"Jobs outside the gate: {text}")
    if text := _repos_with_jobs(audits, "red"):
        lines.append(f"Red default branch: {text}")
    return lines
