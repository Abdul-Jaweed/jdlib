"""Where a security event goes, and the rule that it can never change an outcome.

The library ships sinks, not a policy about which emitter an application installs. A boundary
therefore takes an optional emitter, and every boundary is expected to be able to run without
one - telemetry and audit are configuration, not preconditions for serving a request.

Two properties are deliberate. An emitter that raises does not change what the caller does: a
refusal is still raised and a success still returns, because an audit outage that turns into an
outage of the operation is worse than the gap it was trying to record. And a missing emitter is
reported as *not delivered* rather than silently counted as recorded - `emit_safely` returns
whether the event actually reached the emitter, so a test can tell the two apart.
"""

from __future__ import annotations

import asyncio
from typing import Protocol

from jdlib.security.audit.events import SecurityAuditEvent


class SecurityEventEmitter(Protocol):
    """Anything that accepts a security event: a sink, a queue, a test recorder."""

    def __call__(self, event: SecurityAuditEvent) -> None: ...


def emit_safely(emitter: SecurityEventEmitter | None, event: SecurityAuditEvent) -> bool:
    """Deliver one event, and never let the delivery change the caller's outcome."""
    if emitter is None:
        return False
    try:
        emitter(event)
    except Exception:  # noqa: BLE001 - an audit outage is not the caller's failure
        return False
    return True


class AsyncSinkEmitter:
    """Drives an async sink from a synchronous boundary.

    The successor boundaries are synchronous - a compiler, a registry, a rotating provider -
    and the library's sinks are coroutines, so something has to bridge them. This schedules the
    emit on the running loop and holds a reference until it completes, because an unreferenced
    task can be collected mid-flight and the audit record would simply vanish.

    With no running loop there is nothing to schedule on, and inventing a thread pool to hide
    that would put events out of order and out of the request's lifetime. It raises instead, so
    `emit_safely` reports the event as not delivered - which is the truth.
    """

    def __init__(self, sink: object) -> None:
        self._sink = sink
        self._pending: set[asyncio.Task[None]] = set()

    def __call__(self, event: SecurityAuditEvent) -> None:
        loop = asyncio.get_running_loop()
        task = loop.create_task(self._sink.emit(event))  # type: ignore[attr-defined]
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def drain(self) -> None:
        """Wait for everything scheduled so far. Called on shutdown, never on the hot path."""
        while self._pending:
            await asyncio.gather(*tuple(self._pending), return_exceptions=True)

    @property
    def pending(self) -> int:
        return len(self._pending)
