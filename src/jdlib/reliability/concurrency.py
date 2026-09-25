"""A bounded number of operations at once, refusing rather than queueing without limit (§22, §25).

§25 asks for concurrency control and §22 for rate limits where required. The reliability package
already owns retries, backoff, budgets, breaking and shutdown; it had no concurrency primitive, and
the programme's rule is to extend that package rather than invent one beside it — two limiters are
two things to keep in step, and the one nobody configured is the one that admits everything.

Two decisions shape the gate:

* **the bound is stated, never defaulted.** Constructing a gate without a limit is refused at
  construction, because "we forgot to configure it" is not a failure mode a limiter should have;
* **waiting is bounded too.** A saturated gate that queues forever converts an overload into a
  hang: the caller cannot tell "busy" from "broken", and the work behind it ages. The gate waits
  up to a declared deadline and then refuses, so the caller is told which one it was.

Release happens on the way out whether the body succeeded or raised — a limiter that leaks a slot
on the error path permanently shrinks under exactly the load it exists for.
"""

from __future__ import annotations

import asyncio

from jdlib.errors import JdlibError


class ConcurrencyLimitError(JdlibError):
    """The gate is saturated and the declared wait passed.

    Transient by nature: the same call may be attempted again once in-flight work drains. It is
    deliberately *not* a timeout of the work itself — nothing ran — and the distinction is what
    lets a caller retry this and not a partial operation.
    """


class ConcurrencyGate:
    """An async bound on how many operations run at once, with a bounded wait.

    Used as a context manager: entering admits or refuses, leaving releases.
    """

    def __init__(self, *, limit: int, wait_timeout: float) -> None:
        if limit <= 0:
            raise ValueError("a concurrency limit is a positive number of operations")
        if wait_timeout <= 0:
            raise ValueError("a wait deadline is a positive number of seconds")
        self._limit = limit
        self._wait_timeout = wait_timeout
        self._semaphore = asyncio.Semaphore(limit)
        self._in_flight = 0

    @property
    def limit(self) -> int:
        """The stated bound."""
        return self._limit

    @property
    def in_flight(self) -> int:
        """How many operations hold a slot right now."""
        return self._in_flight

    async def __aenter__(self) -> ConcurrencyGate:
        try:
            await asyncio.wait_for(self._semaphore.acquire(), timeout=self._wait_timeout)
        except TimeoutError as exc:
            raise ConcurrencyLimitError(
                f"the concurrency gate is saturated at {self._limit}"
            ) from exc
        self._in_flight += 1
        return self

    async def __aexit__(self, *exc: object) -> bool:
        self._in_flight -= 1
        self._semaphore.release()
        return False
