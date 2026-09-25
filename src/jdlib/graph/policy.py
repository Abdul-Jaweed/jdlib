"""What bounds a graph call, and what happens when it fails (successor §16; directive §15).

The connector policy established the idiom — a frozen, constructor-validated config handed to an
adapter, with the same field names — and this is that shape for graph calls. It carries no
reliability machinery of its own: the retryability classifier, the backoff, the shared token
budget and the breaker state machine all live in ``jdlib.reliability``, and what stays here is
the part that is genuinely about a graph — which statements may be repeated, and what a retry
must carry.

The rule the composition exists to keep: a retry runs under the context the call was made with,
and a write whose outcome is unknown is not repeated.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from jdlib.graph.errors import GraphCircuitOpenError, GraphError, GraphValidationError
from jdlib.graph.query import GraphQuery
from jdlib.reliability import RetryBudget, RetryBudgetExhaustedError
from jdlib.reliability.breaker import BreakerPolicy
from jdlib.reliability.breaker import CircuitBreaker as SharedCircuitBreaker
from jdlib.reliability.policy import backoff_seconds, is_retryable_failure
from jdlib.security.context import SecurityContext, security_context_scope

if TYPE_CHECKING:  # the client imports this module for its policy: annotations only, no cycle
    from jdlib.graph.client import GraphClient, GraphRunner
    from jdlib.graph.transaction import GraphTransaction


@dataclass(frozen=True, slots=True)
class GraphPolicy:
    """Timeouts, retries and a circuit breaker for graph calls.

    ``statement_timeout`` is the deadline a statement is held to on both sides: the client stops
    waiting at it and the server is told to stop working at it, so a slow statement is abandoned
    rather than left running behind a caller that has already given up.
    """

    statement_timeout: float = 30.0
    max_attempts: int = 3
    retry_backoff: timedelta = timedelta(milliseconds=200)
    failure_threshold: int = 5
    reset_after: timedelta = timedelta(seconds=60)
    #: Shared across every call this policy serves. ``max_attempts`` bounds one call; this bounds
    #: the retries across all of them, which is the amplification a failing dependency suffers.
    retry_budget: RetryBudget | None = None

    def __post_init__(self) -> None:
        if self.statement_timeout <= 0:
            raise GraphValidationError("statement_timeout must be positive")
        if self.max_attempts < 1:
            raise GraphValidationError("max_attempts must be at least 1")
        if self.failure_threshold < 1:
            raise GraphValidationError("failure_threshold must be at least 1")
        if self.reset_after <= timedelta(0):
            raise GraphValidationError("reset_after must be positive")

    async def run(
        self,
        runner: GraphRunner,
        *,
        query: GraphQuery,
        context: SecurityContext,
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        jitter: Callable[[float, float], float] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> list[dict[str, Any]]:
        """Attempt a statement within the budget, then raise. Never return nothing.

        The same context and the same statement object go to every attempt: a retry cannot carry
        a different tenant, and it cannot carry a different statement. Each attempt also runs
        inside that context, so anything the runner does — a metric, an audit record — attributes
        to the caller rather than to nothing.
        """
        wait = sleeper or asyncio.sleep
        choose = jitter or (lambda low, high: (low + high) / 2)
        now = clock or (lambda: datetime.now(tz=UTC))
        for attempt in range(1, self.max_attempts + 1):
            try:
                with security_context_scope(context):
                    return await runner.run(query=query, context=context)
            except GraphError as exc:
                if attempt == self.max_attempts or not self.retryable(exc):
                    raise
                if self.retry_budget is not None and not self.retry_budget.take(now=now()):
                    raise RetryBudgetExhaustedError(
                        f"the retry budget is spent after {attempt} attempt(s); the failure is "
                        f"{type(exc).__name__}"
                    ) from exc
                await wait(backoff_seconds(self.retry_backoff, attempt, choose))
        raise GraphError("the attempt budget was exhausted")  # pragma: no cover - defensive

    async def run_transaction(
        self,
        client: GraphClient,
        *,
        context: SecurityContext,
        work: Callable[[GraphTransaction], Awaitable[None]],
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        jitter: Callable[[float, float], float] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Run a unit of work in its own transaction, retrying only what can be repeated.

        Each attempt gets a fresh transaction, so a failure rolls back cleanly and the retry
        starts from nothing. The retry decision is the transaction's own outcome rather than the
        error's classification alone: a transaction that rolled back may be attempted again, and
        one that committed — or whose commit failed, leaving the outcome uncertain — never is.
        """
        wait = sleeper or asyncio.sleep
        choose = jitter or (lambda low, high: (low + high) / 2)
        now = clock or (lambda: datetime.now(tz=UTC))
        for attempt in range(1, self.max_attempts + 1):
            transaction = client.begin(context=context)
            try:
                async with transaction:
                    with security_context_scope(context):
                        await work(transaction)
            except GraphError as exc:
                if (
                    transaction.retryable()
                    and attempt < self.max_attempts
                    and self.retryable(exc)
                ):
                    if self.retry_budget is not None and not self.retry_budget.take(now=now()):
                        raise RetryBudgetExhaustedError(
                            f"the retry budget is spent after {attempt} attempt(s); the failure "
                            f"is {type(exc).__name__}"
                        ) from exc
                    await wait(backoff_seconds(self.retry_backoff, attempt, choose))
                    continue
                raise
            return
        raise GraphError("the attempt budget was exhausted")  # pragma: no cover - defensive

    retryable = staticmethod(is_retryable_failure)

    def breaker(self, clock: Callable[[], datetime]) -> GraphCircuitBreaker:
        return GraphCircuitBreaker(policy=self, clock=clock)


class GraphCircuitBreaker:
    """The graph's view of the shared breaker: it decides *what* a refused call means.

    The states and their transitions live in ``jdlib.reliability.breaker``, the same state
    machine the connector framework and the job dispatcher use. What stays here is the part that
    is genuinely about the graph: retries through :class:`GraphPolicy`, and
    :class:`GraphCircuitOpenError` as the refusal a caller sees.
    """

    def __init__(self, *, policy: GraphPolicy, clock: Callable[[], datetime]) -> None:
        self._policy = policy
        self._state = SharedCircuitBreaker(
            policy=BreakerPolicy(
                failure_threshold=policy.failure_threshold, reset_after=policy.reset_after
            ),
            clock=clock,
        )

    @property
    def is_open(self) -> bool:
        return self._state.is_open

    async def run(
        self,
        runner: GraphRunner,
        *,
        query: GraphQuery,
        context: SecurityContext,
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        jitter: Callable[[float, float], float] | None = None,
    ) -> list[dict[str, Any]]:
        if not self._state.allow():
            raise GraphCircuitOpenError(
                "the circuit is open after repeated failures; refusing without attempting"
            )
        try:
            result = await self._policy.run(
                runner, query=query, context=context, sleeper=sleeper, jitter=jitter
            )
        except GraphError:
            self._state.record_failure()
            raise
        self._state.record_success()
        return result
