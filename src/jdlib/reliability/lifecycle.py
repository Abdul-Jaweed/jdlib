"""Shutdown: whether work may start, and what the work already running did.

Neither question is answerable from a single component. A library with retries, background jobs
and pending audit writes has to stop admitting work, wait a bounded time for what is in flight,
and *report* what it could not finish. The alternative - exiting and letting the operating system
sort it out - loses an audit write with no record that it was lost, which is the failure the
audit bridge's own drain was already written to avoid.

The report keeps three outcomes apart because they mean different things: a hook that says "I left
N behind" delivered what it could; a hook that raised is a component that failed; and a hook that
never returned was abandoned at the deadline. Collapsing them into "shutdown finished" is exactly
the claim this module exists to refuse to make.

The hooks run concurrently against one shared deadline - not one after another, because a shutdown
that fans out sequentially lets the first slow component starve the rest, and not each with its own
deadline, because N components times a timeout is not a bound.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from jdlib.errors import JdlibError


class ShutdownInProgressError(JdlibError):
    """Work was offered after the shutdown began, and was refused."""


DrainHook = Callable[[], Awaitable[int]]


@dataclass(frozen=True, slots=True)
class ShutdownReport:
    """What a shutdown left behind, by name."""

    drained: Mapping[str, int]
    failed: Mapping[str, str]
    abandoned: Mapping[str, str]

    @property
    def is_clean(self) -> bool:
        """True only when every hook reported nothing left, none raised, none was abandoned."""
        return not any(self.drained.values()) and not self.failed and not self.abandoned

    def summary(self) -> str:
        """One line for a log, because a shutdown that lost something should be greppable."""
        if self.is_clean:
            return "shutdown clean"
        parts = [
            f"{name}: {count} unfinished" for name, count in sorted(self.drained.items()) if count
        ]
        parts += [f"{name}: failed ({kind})" for name, kind in sorted(self.failed.items())]
        parts += [f"{name}: abandoned ({why})" for name, why in sorted(self.abandoned.items())]
        return "; ".join(parts)


class ShutdownCoordinator:
    """The one place that knows whether work is admitted and what is still draining."""

    def __init__(self, *, timeout: float = 5.0) -> None:
        if timeout <= 0:
            raise JdlibError("a shutdown deadline must be positive")
        self._timeout = timeout
        self._hooks: list[tuple[str, DrainHook]] = []
        self._accepting = True

    @property
    def accepting(self) -> bool:
        return self._accepting

    def register(self, name: str, drain: DrainHook) -> None:
        """Register a drain hook. Registering while shutting down is refused."""
        if not self._accepting:
            raise ShutdownInProgressError(
                "the shutdown has begun: a drain registered now would never be run"
            )
        if any(existing == name for existing, _ in self._hooks):
            raise JdlibError(f"{name} is already registered")
        self._hooks.append((name, drain))

    def stop_accepting(self) -> None:
        """Refuse new work from here on. Idempotent, because shutdown is called twice."""
        self._accepting = False

    def admit(self) -> None:
        """Gate for anything that starts work: fails closed once the shutdown began."""
        if not self._accepting:
            raise ShutdownInProgressError(
                "the process is shutting down; new work is refused rather than accepted and dropped"
            )

    async def drain(self) -> ShutdownReport:
        """Stop accepting, wait for every hook within one shared deadline, report the outcome."""
        self.stop_accepting()
        if not self._hooks:
            empty: Mapping[str, str] = MappingProxyType({})
            return ShutdownReport(
                drained=MappingProxyType({}), failed=empty, abandoned=empty
            )

        by_task = {asyncio.ensure_future(hook()): name for name, hook in self._hooks}
        _, pending = await asyncio.wait(set(by_task), timeout=self._timeout)
        for task in pending:
            task.cancel()
        if pending:
            # Await the cancellations: a task destroyed while pending is an unraisable warning
            # under the gate's warning flags, and the shutdown path is not where noise belongs.
            await asyncio.gather(*pending, return_exceptions=True)

        drained: dict[str, int] = {}
        failed: dict[str, str] = {}
        abandoned: dict[str, str] = {}
        for task, name in by_task.items():
            if task in pending:
                abandoned[name] = "did not return before the deadline"
                continue
            error = task.exception()
            if error is not None:
                failed[name] = type(error).__name__
            else:
                drained[name] = int(task.result())
        return ShutdownReport(
            drained=MappingProxyType(drained),
            failed=MappingProxyType(failed),
            abandoned=MappingProxyType(abandoned),
        )
