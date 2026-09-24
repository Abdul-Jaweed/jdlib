"""The retry policy the connector and the job dispatcher both follow.

Two rules, in one place because they were about to live in two: what counts as a retryable
failure, and how long to wait before the next attempt. The taxonomy is the library's own -
`jdlib.security.errors.is_retryable` first, the error's own `transient` flag second - and the
wait is exponential with full jitter, the shape the authn provider already uses.

A second copy of either would be a second answer to the same question, and two answers drift.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

from jdlib.security.errors import is_retryable


def is_retryable_failure(exc: BaseException) -> bool:
    """The taxonomy first, the error's own flag second: one classification, not two."""
    if is_retryable(exc):
        return True
    return bool(getattr(exc, "transient", False))


def backoff_seconds(
    backoff: timedelta, attempt: int, jitter: Callable[[float, float], float]
) -> float:
    """Exponential backoff with full jitter: the ceiling doubles, the wait is drawn under it."""
    ceiling = backoff.total_seconds() * (2 ** (attempt - 1))
    return jitter(0.0, ceiling)
