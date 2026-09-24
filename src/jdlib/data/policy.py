from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from jdlib.data.errors import CircuitOpenError, ConnectorError, ConnectorTimeoutError
from jdlib.reliability import RetryBudget, RetryBudgetExhaustedError
from jdlib.security.context import current_security_context_or_none, security_context_scope
from jdlib.security.errors import is_retryable


class _Attemptable(Protocol):
    async def execute(
        self, *, statement: str, params: tuple[Any, ...] = ()
    ) -> list[dict[str, Any]]: ...


def _sleep_seconds(
    backoff: timedelta, attempt: int, jitter: Callable[[float, float], float]
) -> float:
    """Exponential backoff with full jitter, the same shape the authn provider already uses."""
    ceiling = backoff.total_seconds() * (2 ** (attempt - 1))
    return jitter(0.0, ceiling)


@dataclass(frozen=True, slots=True)
class ConnectionPolicy:
    """Timeouts, retries and a circuit breaker for connector calls.

    This extends the idiom the reliability inventory found already in place - a frozen,
    constructor-validated config; an injected clock and sleeper so tests need no real time;
    fail-closed exhaustion that raises rather than returning nothing - and adds the two
    things that were genuinely absent: circuit breaking and half-open recovery.
    """

    connect_timeout: float = 10.0
    statement_timeout: float = 30.0
    max_attempts: int = 3
    retry_backoff: timedelta = timedelta(milliseconds=200)
    failure_threshold: int = 5
    reset_after: timedelta = timedelta(seconds=60)
    #: Shared across every call this policy serves. ``max_attempts`` bounds one call; this bounds
    #: the retries across all of them, which is the amplification a failing dependency suffers.
    retry_budget: RetryBudget | None = None

    def __post_init__(self) -> None:
        if self.connect_timeout <= 0:
            raise ConnectorError("connect_timeout must be positive")
        if self.statement_timeout <= 0:
            raise ConnectorError("statement_timeout must be positive")
        if self.max_attempts < 1:
            raise ConnectorError("max_attempts must be at least 1")
        if self.failure_threshold < 1:
            raise ConnectorError("failure_threshold must be at least 1")
        if self.reset_after <= timedelta(0):
            raise ConnectorError("reset_after must be positive")

    async def run(
        self,
        connector: _Attemptable,
        *,
        statement: str,
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        jitter: Callable[[float, float], float] | None = None,
        params: tuple[Any, ...] = (),
        clock: Callable[[], datetime] | None = None,
    ) -> list[dict[str, Any]]:
        """Attempt an operation within the budget, then raise. Never return nothing.

        Every attempt runs inside the security context the call started with, and every retry
        costs a token from the shared budget - both were recorded absent before this.
        """
        wait = sleeper or asyncio.sleep
        choose = jitter or (lambda low, high: (low + high) / 2)
        now = clock or (lambda: datetime.now(tz=UTC))
        # Captured once, re-established around every attempt: a retry that ran without the context
        # the original call had would be a retry that can reach another tenant's rows. Capturing it
        # here rather than relying on the ambient value is what makes that true across a boundary
        # that drops context - a thread, a spawned task, a queue hop.
        context = current_security_context_or_none()
        for attempt in range(1, self.max_attempts + 1):
            try:
                with (
                    security_context_scope(context) if context is not None else nullcontext()
                ):
                    return await connector.execute(statement=statement, params=params)
            except ConnectorError as exc:
                if attempt == self.max_attempts or not self._retryable(exc):
                    raise
                if self.retry_budget is not None and not self.retry_budget.take(now=now()):
                    raise RetryBudgetExhaustedError(
                        f"the retry budget is spent after {attempt} attempt(s); the failure is "
                        f"{type(exc).__name__}"
                    ) from exc
                await wait(_sleep_seconds(self.retry_backoff, attempt, choose))
        raise ConnectorError("the attempt budget was exhausted")  # pragma: no cover - defensive

    @staticmethod
    def _retryable(exc: ConnectorError) -> bool:
        """The taxonomy first, the error's own flag second: one classification, not two."""
        if is_retryable(exc):
            return True
        return bool(getattr(exc, "transient", False))

    def raise_for_timeout(self, *, elapsed: float, operation: str) -> None:
        if elapsed > self.statement_timeout:
            raise ConnectorTimeoutError(
                f"{operation} took {elapsed:.3f}s, over the "
                f"{self.statement_timeout}s policy timeout"
            )

    def breaker(self, clock: Callable[[], datetime]) -> CircuitBreaker:
        return CircuitBreaker(policy=self, clock=clock)


class CircuitBreaker:
    """Refuses calls while a dependency is failing, and probes it once the window has passed.

    Closed -> Open after ``failure_threshold`` consecutive failures. Open -> Half-open after
    ``reset_after``, where exactly one call is allowed through: success closes the circuit,
    failure opens it again. Without the half-open step a breaker either never recovers or
    recovers into a dependency that is still down.
    """

    def __init__(self, *, policy: ConnectionPolicy, clock: Callable[[], datetime]) -> None:
        self._policy = policy
        self._clock = clock
        self._failures = 0
        self._opened_at: datetime | None = None
        self._half_open = False

    @property
    def is_open(self) -> bool:
        return self._opened_at is not None and not self._half_open

    def _half_open_allowed(self) -> bool:
        if self._opened_at is None:
            return True
        if self._half_open:
            return False
        if self._clock() - self._opened_at >= self._policy.reset_after:
            self._half_open = True
            return True
        return False

    async def run(
        self,
        connector: _Attemptable,
        *,
        statement: str = "probe",
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        params: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        if not self._half_open_allowed():
            raise CircuitOpenError(
                "the circuit is open after repeated failures; refusing without attempting"
            )
        try:
            result = await self._policy.run(
                connector, statement=statement, sleeper=sleeper, params=params
            )
        except ConnectorError:
            self._failures += 1
            if self._half_open or self._failures >= self._policy.failure_threshold:
                self._opened_at = self._clock()
                self._half_open = False
            raise
        self._failures = 0
        self._opened_at = None
        self._half_open = False
        return result
