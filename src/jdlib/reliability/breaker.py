"""The breaker as a state machine, usable by anything that retries.

Since §6 the connector has had closed -> open -> half-open, inside `ConnectionPolicy`
and shaped by it: its states were reached through `run(connector, statement=...)`. The
reliability inventory's remaining open item was that recovery *outside* the connector
policy did not exist - a job dispatcher or a sink had backoff and a budget but no state,
so a dead dependency was retried for as long as the budget allowed, on every call.

The state machine lives here so there is one implementation and the connector consults
it rather than keeping a second. What a caller does with "refused" - fail fast, degrade,
queue - is the caller's decision, and deliberately not this class's: a breaker that
knows what a refused call should do has become a component.

Time is injected, as everywhere else in this library that expires.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from jdlib.errors import JdlibError


class BreakerState(StrEnum):
    """Closed admits, open refuses, half-open admits exactly one trial."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


@dataclass(frozen=True, slots=True)
class BreakerPolicy:
    """When to open, and how long to wait before probing.

    Defaults match the connector's (`ConnectionPolicy`), because a second set of
    defaults for the same question would be a second answer to it.
    """

    failure_threshold: int = 5
    reset_after: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if self.failure_threshold < 1:
            raise JdlibError("a breaker that opens on no failures is always open")
        if self.reset_after <= timedelta(0):
            raise JdlibError("a breaker whose window never passes never recovers")


class CircuitBreaker:
    """Closed -> Open after ``failure_threshold`` consecutive failures.

    Open -> Half-open after ``reset_after``, where **exactly one** call is admitted:
    success closes the circuit, failure opens it again. A window that let every caller
    through would not be half-open, it would be open with a delay - and a dependency
    that is still down would take the whole burst.

    Not thread-safe by itself: one breaker per event loop, which is how the callers
    that need it are arranged.
    """

    def __init__(
        self, *, policy: BreakerPolicy | None = None, clock: Callable[[], datetime]
    ) -> None:
        self._policy = policy or BreakerPolicy()
        self._clock = clock
        self._failures = 0
        self._opened_at: datetime | None = None
        self._trial_in_flight = False

    @property
    def state(self) -> BreakerState:
        if self._opened_at is None:
            return BreakerState.CLOSED
        return BreakerState.HALF_OPEN if self._trial_in_flight else BreakerState.OPEN

    @property
    def is_open(self) -> bool:
        """True when a call would be refused right now. Refusal *is* the refusal."""
        return self.state is BreakerState.OPEN

    def allow(self) -> bool:
        """May this call proceed? In half-open, the first caller to ask is the trial."""
        if self._opened_at is None:
            return True
        if self._trial_in_flight:
            return False
        if self._clock() - self._opened_at >= self._policy.reset_after:
            self._trial_in_flight = True
            return True
        return False

    def record_success(self) -> None:
        """The dependency answered: closed, and the failure count is forgotten."""
        self._failures = 0
        self._opened_at = None
        self._trial_in_flight = False

    def record_failure(self) -> None:
        """A failure: trip at the threshold, and a failed trial trips immediately."""
        self._failures += 1
        if self._trial_in_flight or self._failures >= self._policy.failure_threshold:
            self._opened_at = self._clock()
            self._trial_in_flight = False
