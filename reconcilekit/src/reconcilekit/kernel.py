"""The reconciliation kernel: a fetch-then-branch skeleton for one target, and
a bounded-parallel runner over a fleet of them with per-target failure
isolation. Nothing here knows what a target is beyond its name.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from rich.progress import MofNCompleteColumn, Progress

from .render import console, print_status, progress_bar, progress_description
from .status import QUIET_STATUSES, Status

DEFAULT_JOBS = 6


class ReconcileError(RuntimeError):
    """A target's worker failed, or a run finished with failures.

    Callers that need a domain-specific exception type (so `pytest.raises` and
    `except` clauses can stay narrow) pass it as `run_parallel(..., error_cls=)`.
    """


class HasName(Protocol):
    """The minimal shape `run_parallel` needs from a target: something to
    label progress lines and failure messages with.
    """

    @property
    def name(self) -> str: ...


class ResultLike(Protocol):
    """The minimal shape `run_parallel` needs from a worker's return value --
    `Result` satisfies this, but a caller can return its own type instead as
    long as it carries these two fields.
    """

    status: Status
    line: str


@dataclass
class Result[Target: HasName]:
    """A worker's return value: `target` and `line` for reporting, `status`
    for classification/suppression, and an optional `tag` for a caller's own
    end-of-run bookkeeping (distinct from `status`, which is exit-code plumbing).
    """

    target: Target
    line: str
    status: Status = Status.OK
    tag: str | None = None


async def run_reconcile[State, R: ResultLike](
    *,
    dry_run: bool,
    fetch: Callable[[], Awaitable[State]],
    plan_result: Callable[[State], R],
    apply_result: Callable[[State], Awaitable[R]],
) -> R:
    """Read the target's current state once, then either report the plan (dry
    run) or apply the change and report the outcome. Each worker keeps its own
    planning, side effects, and result formatting in the three callables.
    """
    state = await fetch()
    if dry_run:
        return plan_result(state)
    return await apply_result(state)


async def run_parallel[Target: HasName, R: ResultLike](
    targets: Sequence[Target],
    worker: Callable[[Target], Awaitable[R]],
    *,
    jobs: int = DEFAULT_JOBS,
    verbose: bool = False,
    dry_run: bool = False,
    error_cls: type[Exception] = ReconcileError,
    fatal: type[Exception] | tuple[type[Exception], ...] = (),
) -> list[R]:
    """Runs worker(target) for each target concurrently (bounded by a semaphore
    -- these are I/O-bound calls, not CPU-bound work), printing each result's
    line as soon as it's ready (completion order, not submission order) above a
    live progress bar, and returning every result.

    A worker exception is caught inside call() itself -- not left to propagate
    through the TaskGroup -- so one target failing doesn't cancel the others
    (TaskGroup cancels every sibling task the moment any task raises). Instead
    it's printed as a failure line and collected; once every target has been
    attempted, any failures are raised together as a single `error_cls` so the
    run still ends with a nonzero exit. `error_cls` must be constructible from
    a single positional `str` -- the type hint (`type[Exception]`) doesn't
    capture that narrower contract, but the call below relies on it.

    Unless verbose=True, a target already at its target state (UNCHANGED /
    LIMITED_UNCHANGED) isn't printed live -- on a large fleet the handful of
    lines that represent an actual change would otherwise be lost in a wall of
    "unchanged: ..." lines. Suppressed lines are counted and reported as a
    single dim summary line instead. The changed targets (OK / LIMITED) are
    tallied on their own line too -- "N changed", or "N would change" when
    `dry_run=True`.

    A `fatal` exception (e.g. an exhausted API rate limit, which every
    remaining target would hit too) stops the run instead: targets not yet
    started are skipped, and the first fatal exception is re-raised as-is,
    once, rather than as one failure line per target.

    `jobs`/`verbose`/`dry_run`/`error_cls`/`fatal` are keyword-only so a bare
    positional bool at a call site can't be misread as one or the other.
    """
    results: list[R] = []
    failed_names: list[str] = []
    fatal_errors: list[Exception] = []
    unchanged_count = 0
    active: set[str] = set()
    sem = asyncio.Semaphore(jobs)

    with progress_bar(
        *Progress.get_default_columns(), MofNCompleteColumn()
    ) as progress:
        task = progress.add_task(progress_description(active), total=len(targets))

        async def call(target: Target) -> None:
            nonlocal unchanged_count
            async with sem:
                if fatal_errors:
                    return
                active.add(target.name)
                progress.update(task, description=progress_description(active))
                try:
                    result = await worker(target)
                except fatal as exc:
                    fatal_errors.append(exc)
                except Exception as exc:  # noqa: BLE001 -- collected below, not swallowed
                    failed_names.append(target.name)
                    print_status(Status.FAILED, f"{target.name}: {exc}")
                else:
                    if not verbose and result.status in QUIET_STATUSES:
                        unchanged_count += 1
                    else:
                        print_status(result.status, result.line)
                    results.append(result)
                finally:
                    active.discard(target.name)
                    progress.advance(task)
                    progress.update(task, description=progress_description(active))

        async with asyncio.TaskGroup() as tg:
            for target in targets:
                tg.create_task(call(target))

    if fatal_errors:
        raise fatal_errors[0]

    changed = sum(1 for r in results if r.status not in QUIET_STATUSES)
    if changed:
        console.print(
            f"  {changed} {'would change' if dry_run else 'changed'}",
            style="bold",
        )
    if unchanged_count:
        console.print(
            f"  {unchanged_count} unchanged (rerun with --verbose to see them)",
            style="dim",
        )

    if failed_names:
        raise error_cls(
            f"{len(failed_names)} target(s) failed: {', '.join(sorted(failed_names))}"
        )

    return results
