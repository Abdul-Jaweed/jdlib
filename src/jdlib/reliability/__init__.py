"""The two reliability areas the inventory found absent, and nothing else.

`budget` answers "how many retries is this system willing to spend", across calls rather than
within one. `lifecycle` answers "may new work start, and what did the work already running do" -
the shutdown path. Both live in their own namespace so the pinned public surface of `jdlib`
itself does not move.
"""

from jdlib.reliability.budget import RetryBudget, RetryBudgetExhaustedError
from jdlib.reliability.lifecycle import (
    DrainHook,
    ShutdownCoordinator,
    ShutdownInProgressError,
    ShutdownReport,
)

__all__ = [
    "DrainHook",
    "RetryBudget",
    "RetryBudgetExhaustedError",
    "ShutdownCoordinator",
    "ShutdownInProgressError",
    "ShutdownReport",
]
