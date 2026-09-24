"""A retry budget: the limit a per-call attempt count cannot express.

`max_attempts` bounds one call. A budget bounds retries *across* calls, which is the difference
that matters when a dependency starts failing: every caller retrying its own three attempts
multiplies the load on something already unwell, and the multiplication is what turns a slow
dependency into an outage.

It is deliberately not a rate limit. A token is spent before a *retry*, never before a first
attempt, so the budget can never refuse work that has not already been tried - the failure mode
of a limiter that is consulted in the wrong place.

Time is injected, as it is for everything in this library that expires: a test moves a clock and
the caller chooses the source.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime

from jdlib.errors import JdlibError


class RetryBudgetExhaustedError(JdlibError):
    """A retry was refused because the shared budget had no tokens left.

    Raised with the failure it declined to retry as ``__cause__``. Returning the original error
    would hide the budget; swallowing it would hide the failure; the caller needs both.
    """


@dataclass(slots=True)
class RetryBudget:
    """Tokens shared by every call that consults the same budget.

    A lock, not just an integer: the library dispatches blocking work to threads, so two callers
    can reach this at the same moment and neither is in an event loop.
    """

    capacity: int = 20
    refill_per_second: float = 1.0

    _tokens: float = field(default=0.0, init=False, repr=False)
    _updated: datetime | None = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if self.capacity < 1:
            raise JdlibError("a retry budget with no tokens refuses every retry")
        if self.refill_per_second < 0:
            raise JdlibError("a refill rate cannot be negative")
        self._tokens = float(self.capacity)

    def take(self, *, now: datetime) -> bool:
        """Spend one retry token, or report that there is none. Never waits."""
        with self._lock:
            self._refill(now)
            if self._tokens < 1.0:
                return False
            self._tokens -= 1.0
            return True

    def available(self, *, now: datetime) -> int:
        """Whole tokens left at ``now``, after refilling. Reported, never assumed."""
        with self._lock:
            self._refill(now)
            return int(self._tokens)

    def _refill(self, now: datetime) -> None:
        if self._updated is None:
            self._updated = now
            return
        elapsed = (now - self._updated).total_seconds()
        if elapsed <= 0:
            return
        self._tokens = min(float(self.capacity), self._tokens + elapsed * self.refill_per_second)
        self._updated = now
