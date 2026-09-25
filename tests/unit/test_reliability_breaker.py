"""The breaker, usable by anything that retries - not only by the connector.

`ConnectionPolicy` has had closed -> open -> half-open since §6, and its own tests pin
that. What was recorded as still absent was half-open recovery *outside* the connector
policy: a job dispatcher, a sink, an adapter retrying a flaky dependency had backoff but
no state, so it retried a dead dependency until its budget ran out, every time.

The state machine is extracted here so there is one implementation. The connector now
delegates to it, which is why its existing tests are the other half of this file's net.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from jdlib.errors import JdlibError
from jdlib.reliability.breaker import BreakerPolicy, BreakerState, CircuitBreaker


class _Clock:
    def __init__(self) -> None:
        self._now = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)


def _breaker(*, threshold: int = 3, reset_after: float = 30.0) -> tuple[CircuitBreaker, _Clock]:
    clock = _Clock()
    policy = BreakerPolicy(
        failure_threshold=threshold, reset_after=timedelta(seconds=reset_after)
    )
    return CircuitBreaker(policy=policy, clock=clock), clock


def test_it_starts_closed_and_admits() -> None:
    breaker, _ = _breaker()
    assert breaker.state is BreakerState.CLOSED
    assert breaker.allow() is True


def test_it_opens_after_consecutive_failures_and_refuses_without_being_asked() -> None:
    breaker, _ = _breaker(threshold=3)
    for _ in range(3):
        assert breaker.allow() is True
        breaker.record_failure()
    assert breaker.state is BreakerState.OPEN
    # refused before the dependency is touched at all: the point of a breaker
    assert breaker.allow() is False


def test_one_success_before_the_threshold_forgets_the_failures() -> None:
    breaker, _ = _breaker(threshold=3)
    breaker.record_failure()
    breaker.record_failure()
    breaker.record_success()
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state is BreakerState.CLOSED, "two failures after a success is not a trip"


def test_half_open_admits_exactly_one_trial() -> None:
    """A window that admits every caller is not half-open, it is open with a delay."""
    breaker, clock = _breaker(threshold=2, reset_after=30)
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state is BreakerState.OPEN

    clock.advance(29)
    assert breaker.allow() is False, "the window has not passed"

    clock.advance(2)
    assert breaker.allow() is True, "the trial"
    assert breaker.allow() is False, "and no second caller gets one"
    assert breaker.state is BreakerState.HALF_OPEN


def test_a_successful_trial_closes_and_a_failed_one_reopens() -> None:
    breaker, clock = _breaker(threshold=2, reset_after=30)
    breaker.record_failure()
    breaker.record_failure()

    clock.advance(31)
    assert breaker.allow() is True
    breaker.record_success()
    assert breaker.state is BreakerState.CLOSED
    assert breaker.allow() is True

    breaker.record_failure()
    breaker.record_failure()
    clock.advance(31)
    assert breaker.allow() is True
    breaker.record_failure()  # the trial fails
    assert breaker.state is BreakerState.OPEN
    assert breaker.allow() is False, "a failed trial waits the window out again"


def test_the_policy_refuses_configurations_that_cannot_work() -> None:
    with pytest.raises(JdlibError):
        BreakerPolicy(failure_threshold=0)
    with pytest.raises(JdlibError):
        BreakerPolicy(reset_after=timedelta(0))
