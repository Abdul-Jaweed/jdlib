"""The bridge from a synchronous boundary to an async sink (directive §13).

`AsyncSinkEmitter` exists because the successor boundaries are synchronous while the library's
sinks are coroutines. Its `drain()` had no test until the reference application hung on it: the
app's shutdown hook awaited `drain()`, an event had been scheduled on a *different* event loop
than the one shutting down, and `drain()` waited for that task forever. The live hang is the
evidence this file was missing.

Three properties, one per way a drain can go wrong: it must still wait for its own loop's work,
it must not be able to block shutdown on work it can never await, and it must report what it
left behind rather than implying the queue was empty.
"""

from __future__ import annotations

import asyncio

from jdlib.security.audit import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.audit.emitter import AsyncSinkEmitter


def _event() -> SecurityAuditEvent:
    return SecurityAuditEvent(
        event_type=SecurityEventType.AUTHZ_ALLOW,
        outcome=AuditOutcome.SUCCESS,
        action="read",
        source=AuditSource.API,
    )


class _Recorder:
    """A sink that records what it received, after an optional delay."""

    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.seen: list[SecurityAuditEvent] = []

    async def emit(self, event: SecurityAuditEvent) -> None:
        if self.delay:
            await asyncio.sleep(self.delay)
        self.seen.append(event)


class _GatedSink:
    """A sink that finishes only when the test releases it."""

    def __init__(self) -> None:
        self.gate = asyncio.Event()
        self.seen: list[SecurityAuditEvent] = []

    async def emit(self, event: SecurityAuditEvent) -> None:
        await self.gate.wait()
        self.seen.append(event)


async def test_drain_awaits_what_its_own_loop_scheduled() -> None:
    """The positive control: nothing is reported as left behind, and the event arrived."""
    sink = _Recorder(delay=0.05)
    emitter = AsyncSinkEmitter(sink)

    emitter(_event())

    left = await asyncio.wait_for(emitter.drain(), timeout=2)
    assert left == 0
    assert len(sink.seen) == 1
    assert emitter.pending == 0


def test_an_event_scheduled_on_another_loop_cannot_block_shutdown() -> None:
    """The live defect, in isolation.

    An event scheduled on a loop that is not running can never complete, so awaiting it from the
    shutting-down loop waits forever. This is what the reference application did - and a shutdown
    that can hang on an audit write contradicts the module's own doctrine that an audit gap is
    recorded, never propagated.

    Written as a synchronous test on purpose: the scheduling loop and the shutting-down loop have
    to be different loops, and one loop cannot be driven while another is running.
    """
    sink = _GatedSink()
    emitter = AsyncSinkEmitter(sink)
    other = asyncio.new_event_loop()
    try:
        other.run_until_complete(_schedule(emitter))
        assert emitter.pending == 1

        # `asyncio.run` is a *third* loop: exactly the position the application's shutdown was in.
        left = asyncio.run(asyncio.wait_for(emitter.drain(timeout=0.05), timeout=2))

        assert left == 1, "the undelivered event must be reported, not implied away"
        assert sink.seen == [], "nothing may be recorded for an emit that never ran"
    finally:
        sink.gate.set()
        other.run_until_complete(asyncio.sleep(0))
        assert emitter.pending == 0, "releasing the other loop must not leave the emitter wedged"
        other.close()


async def test_a_sink_that_never_finishes_is_reported_rather_than_waited_on_forever() -> None:
    """The bounded half: a stuck sink inside the *same* loop ends the wait, with a count."""
    sink = _GatedSink()
    emitter = AsyncSinkEmitter(sink)
    emitter(_event())

    left = await asyncio.wait_for(emitter.drain(timeout=0.05), timeout=2)

    assert left == 1
    # Release the gated sink so nothing is left pending when the loop closes.
    sink.gate.set()
    await asyncio.sleep(0)


async def _schedule(emitter: AsyncSinkEmitter) -> None:
    """Schedule one event on whichever loop is driving this coroutine."""
    emitter(_event())
