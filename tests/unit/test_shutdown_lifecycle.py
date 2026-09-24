"""Shutdown: the gate that refuses new work, and the drain that reports what it left.

The inventory recorded shutdown as ABSENT: the library defined no shutdown, drain or close
lifecycle, and nothing stated what happens to an in-flight retry or a pending audit write. The
failure mode that matters is not a slow shutdown - it is a silent one, where a process exits
having lost an audit event and nothing anywhere says so.

So the report keeps three outcomes apart, and each has a test here: a hook that says how much it
could not finish, a hook that raised, and a hook that never returned.
"""

from __future__ import annotations

import asyncio

import pytest

from jdlib.reliability import ShutdownCoordinator, ShutdownInProgressError


async def _clean() -> int:
    return 0


async def _left_two_behind() -> int:
    return 2


async def _raises() -> int:
    raise RuntimeError("the sink is gone")


def _never_returns_factory() -> object:
    async def _never_returns() -> int:
        await asyncio.Event().wait()
        return 0

    return _never_returns


def test_admit_refuses_once_the_shutdown_has_started() -> None:
    coordinator = ShutdownCoordinator()

    coordinator.admit()  # before: work is admitted
    coordinator.stop_accepting()

    assert coordinator.accepting is False
    with pytest.raises(ShutdownInProgressError, match="new work is refused"):
        coordinator.admit()


def test_a_drain_cannot_be_registered_after_the_shutdown_began() -> None:
    """A hook registered during shutdown would never run, so it is refused rather than stored."""
    coordinator = ShutdownCoordinator()
    coordinator.stop_accepting()

    with pytest.raises(ShutdownInProgressError, match="would never be run"):
        coordinator.register("late", _clean)


async def test_drain_reports_a_clean_shutdown() -> None:
    coordinator = ShutdownCoordinator(timeout=1.0)
    coordinator.register("audit", _clean)

    report = await coordinator.drain()

    assert report.is_clean
    assert report.drained == {"audit": 0}
    assert report.summary() == "shutdown clean"
    assert coordinator.accepting is False, "draining stops admission without being asked twice"


async def test_drain_reports_what_a_hook_could_not_finish() -> None:
    coordinator = ShutdownCoordinator(timeout=1.0)
    coordinator.register("audit", _left_two_behind)

    report = await coordinator.drain()

    assert not report.is_clean
    assert report.drained == {"audit": 2}
    assert "audit: 2 unfinished" in report.summary()


async def test_a_hook_that_raises_is_recorded_and_never_propagated() -> None:
    """A failing drain must not stop the others: the shutdown finishes and says what failed."""
    coordinator = ShutdownCoordinator(timeout=1.0)
    coordinator.register("broken", _raises)
    coordinator.register("audit", _clean)

    report = await coordinator.drain()

    assert report.failed == {"broken": "RuntimeError"}
    assert report.drained == {"audit": 0}
    assert not report.is_clean
    assert "broken: failed (RuntimeError)" in report.summary()


async def test_a_hook_that_never_returns_is_abandoned_at_the_deadline() -> None:
    coordinator = ShutdownCoordinator(timeout=0.05)
    coordinator.register("stuck", _never_returns_factory())  # type: ignore[arg-type]

    started = asyncio.get_running_loop().time()
    report = await asyncio.wait_for(coordinator.drain(), timeout=2)
    elapsed = asyncio.get_running_loop().time() - started

    assert report.abandoned == {"stuck": "did not return before the deadline"}
    assert report.drained == {}
    assert elapsed < 1.0, "the deadline is the point: shutdown cannot wait for a stuck component"
    assert "stuck: abandoned" in report.summary()


async def test_the_deadline_bounds_the_whole_shutdown_and_not_each_hook() -> None:
    """Three hooks that each wait longer than the deadline: the shutdown still returns in one."""
    coordinator = ShutdownCoordinator(timeout=0.1)
    for name in ("one", "two", "three"):
        coordinator.register(name, _never_returns_factory())  # type: ignore[arg-type]

    started = asyncio.get_running_loop().time()
    report = await asyncio.wait_for(coordinator.drain(), timeout=2)
    elapsed = asyncio.get_running_loop().time() - started

    assert set(report.abandoned) == {"one", "two", "three"}
    assert elapsed < 1.0, "a per-hook deadline would have taken three times as long"
