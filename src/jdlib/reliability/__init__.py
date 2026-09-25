"""The two reliability areas the inventory found absent, and nothing else.

`budget` answers "how many retries is this system willing to spend", across calls rather than
within one. `lifecycle` answers "may new work start, and what did the work already running do" -
the shutdown path. Both live in their own namespace so the pinned public surface of `jdlib`
itself does not move.
"""

from jdlib.reliability.breaker import BreakerPolicy, BreakerState, CircuitBreaker
from jdlib.reliability.budget import RetryBudget, RetryBudgetExhaustedError
from jdlib.reliability.lifecycle import (
    DrainHook,
    ShutdownCoordinator,
    ShutdownInProgressError,
    ShutdownReport,
)
from jdlib.reliability.policy import backoff_seconds, is_retryable_failure

__all__ = [
    "backoff_seconds",
    "BreakerPolicy",
    "BreakerState",
    "CircuitBreaker",
    "DrainHook",
    "is_retryable_failure",
    "RetryBudget",
    "RetryBudgetExhaustedError",
    "ShutdownCoordinator",
    "ShutdownInProgressError",
    "ShutdownReport",
]
