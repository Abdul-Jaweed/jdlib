"""The reliability composition, and the one retry that must never happen (directive §15).

The library already owns the primitives — the retryability classifier, the backoff, the shared
token budget, the breaker state machine — so this file pins that the graph uses *those* rather
than a second set, and that the composition keeps the two rules the primitives cannot enforce on
their own:

* every attempt runs under the context the call was made with, so a retry cannot reach a tenant
  the caller was not authorised for;
* a transaction that committed is never repeated. A commit that *failed* is not retryable
  either: the server may have applied it before the error arrived, and repeating an uncertain
  write is how a duplicate appears.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from jdlib.graph import (
    GraphCircuitOpenError,
    GraphPolicy,
    GraphQuery,
    GraphTimeoutError,
    GraphTransaction,
    GraphUnavailableError,
    GraphValidationError,
    GraphVocabulary,
    node_match,
)
from jdlib.graph.transaction import TransactionOutcome
from jdlib.reliability import RetryBudget, RetryBudgetExhaustedError
from jdlib.reliability.policy import is_retryable_failure
from jdlib.security.context import current_security_context_or_none
from tests.support.context_fakes import CallableClock
from tests.support.graph_fakes import TENANT_ID, FakeDriver, graph_context

VOCABULARY = GraphVocabulary(
    labels=frozenset({"User"}),
    relationship_types=frozenset({"OWNS"}),
    property_keys=frozenset({"name"}),
)


def _query() -> GraphQuery:
    return node_match(VOCABULARY.label("User"), tenant=str(TENANT_ID), node_id="u1")


class _Runner:
    """A runner that fails a set number of times, and records what it was given."""

    def __init__(self, *, failures: int = 0, error: BaseException | None = None) -> None:
        self.calls: list[tuple[GraphQuery, Any]] = []
        self.ambient: list[Any] = []
        self._remaining = failures
        self._error = error or GraphUnavailableError("the database is unavailable")

    async def run(self, *, query: GraphQuery, context: Any) -> list[dict[str, Any]]:
        self.calls.append((query, context))
        self.ambient.append(current_security_context_or_none())
        if self._remaining > 0:
            self._remaining -= 1
            raise self._error
        return [{"id": "u1"}]


class _Sleeps:
    def __init__(self) -> None:
        self.waits: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.waits.append(seconds)


class _BeginningClient:
    """A client that hands out real transactions over a fake driver session."""

    def __init__(self, driver: FakeDriver) -> None:
        self.driver = driver
        self.transactions: list[GraphTransaction] = []

    def begin(self, *, context: Any) -> GraphTransaction:
        transaction = GraphTransaction(
            session=self.driver.session(), context=context, policy=GraphPolicy()
        )
        self.transactions.append(transaction)
        return transaction


async def test_a_transient_failure_is_retried_and_the_last_answer_wins() -> None:
    runner = _Runner(failures=2)
    policy = GraphPolicy(max_attempts=3)
    rows = await policy.run(runner, query=_query(), context=graph_context())
    assert rows == [{"id": "u1"}]
    assert len(runner.calls) == 3


async def test_a_permanent_failure_is_not_retried() -> None:
    runner = _Runner(failures=1, error=GraphValidationError("refused"))
    with pytest.raises(GraphValidationError):
        await GraphPolicy(max_attempts=3).run(runner, query=_query(), context=graph_context())
    assert len(runner.calls) == 1


async def test_a_timeout_is_retried_only_when_the_operation_says_it_is_safe() -> None:
    """A write whose outcome is unknown must not be repeated by the policy."""
    unknown = _Runner(failures=1, error=GraphTimeoutError("slow"))
    with pytest.raises(GraphTimeoutError):
        await GraphPolicy(max_attempts=3).run(unknown, query=_query(), context=graph_context())
    assert len(unknown.calls) == 1

    safe = _Runner(failures=1, error=GraphTimeoutError("slow", transient=True))
    rows = await GraphPolicy(max_attempts=3).run(safe, query=_query(), context=graph_context())
    assert rows == [{"id": "u1"}]
    assert len(safe.calls) == 2


async def test_the_attempt_budget_is_spent_from_the_shared_budget() -> None:
    runner = _Runner(failures=5)
    budget = RetryBudget(capacity=1, refill_per_second=0.0)
    policy = GraphPolicy(max_attempts=5, retry_budget=budget)
    with pytest.raises(RetryBudgetExhaustedError) as caught:
        await policy.run(runner, query=_query(), context=graph_context())
    assert isinstance(caught.value.__cause__, GraphUnavailableError)
    assert len(runner.calls) == 2


async def test_every_attempt_runs_under_the_context_the_call_was_made_with() -> None:
    runner = _Runner(failures=1)
    context = graph_context()
    await GraphPolicy(max_attempts=2).run(runner, query=_query(), context=context)
    assert [seen for _, seen in runner.calls] == [context, context]
    assert runner.ambient == [context, context]


async def test_the_backoff_grows_with_each_attempt() -> None:
    runner = _Runner(failures=2)
    sleeps = _Sleeps()
    policy = GraphPolicy(max_attempts=3, retry_backoff=timedelta(milliseconds=100))
    await policy.run(
        runner,
        query=_query(),
        context=graph_context(),
        sleeper=sleeps,
        jitter=lambda low, high: high,
    )
    assert sleeps.waits == [0.1, 0.2]


async def test_the_breaker_opens_and_refuses_without_attempting() -> None:
    runner = _Runner(failures=10)
    clock = CallableClock()
    policy = GraphPolicy(max_attempts=1, failure_threshold=2, reset_after=timedelta(seconds=30))
    breaker = policy.breaker(clock)
    for _ in range(2):
        with pytest.raises(GraphUnavailableError):
            await breaker.run(runner, query=_query(), context=graph_context())
    assert breaker.is_open is True
    calls_before = len(runner.calls)
    with pytest.raises(GraphCircuitOpenError):
        await breaker.run(runner, query=_query(), context=graph_context())
    assert len(runner.calls) == calls_before


async def test_the_breaker_allows_a_probe_after_the_reset_window() -> None:
    runner = _Runner(failures=2)
    clock = CallableClock()
    policy = GraphPolicy(max_attempts=1, failure_threshold=2, reset_after=timedelta(seconds=30))
    breaker = policy.breaker(clock)
    for _ in range(2):
        with pytest.raises(GraphUnavailableError):
            await breaker.run(runner, query=_query(), context=graph_context())
    assert breaker.is_open is True
    clock.advance(timedelta(seconds=31))
    await breaker.run(runner, query=_query(), context=graph_context())
    assert breaker.is_open is False


async def test_a_transaction_that_rolled_back_is_retried() -> None:
    client = _BeginningClient(FakeDriver())
    attempts: list[int] = []

    async def work(transaction: GraphTransaction) -> None:
        attempts.append(1)
        if len(attempts) < 2:
            raise GraphUnavailableError("transient")
        await transaction.run(query=_query(), context=graph_context())

    await GraphPolicy(max_attempts=3).run_transaction(
        client, context=graph_context(), work=work
    )
    assert len(attempts) == 2
    assert len(client.transactions) == 2
    assert client.transactions[0].outcome is TransactionOutcome.ROLLED_BACK
    assert client.transactions[1].outcome is TransactionOutcome.COMMITTED


async def test_a_transaction_that_committed_is_never_repeated() -> None:
    client = _BeginningClient(FakeDriver())

    async def work(transaction: GraphTransaction) -> None:
        await transaction.commit()
        raise GraphUnavailableError("the caller failed after the commit landed")

    with pytest.raises(GraphUnavailableError):
        await GraphPolicy(max_attempts=3).run_transaction(
            client, context=graph_context(), work=work
        )
    assert len(client.transactions) == 1
    assert client.transactions[0].outcome is TransactionOutcome.COMMITTED


async def test_a_failed_commit_is_uncertain_and_not_repeated() -> None:
    """The commit may have landed before the error: repeating it is how a duplicate appears."""
    driver = FakeDriver()
    client = _BeginningClient(driver)

    async def work(transaction: GraphTransaction) -> None:
        assert driver.transaction is not None
        driver.transaction.commit_error = GraphUnavailableError(
            "the connection dropped during commit"
        )

    with pytest.raises(GraphUnavailableError):
        await GraphPolicy(max_attempts=3).run_transaction(
            client, context=graph_context(), work=work
        )
    assert len(client.transactions) == 1
    assert client.transactions[0].outcome is TransactionOutcome.UNCERTAIN
    assert client.transactions[0].retryable() is False


async def test_the_loop_stops_at_max_attempts_and_raises_the_failure() -> None:
    runner = _Runner(failures=10)
    with pytest.raises(GraphUnavailableError):
        await GraphPolicy(max_attempts=2).run(runner, query=_query(), context=graph_context())
    assert len(runner.calls) == 2


def test_the_policy_validates_its_bounds() -> None:
    for bad in (
        {"statement_timeout": 0},
        {"max_attempts": 0},
        {"failure_threshold": 0},
        {"reset_after": timedelta(0)},
    ):
        with pytest.raises(GraphValidationError):
            GraphPolicy(**bad)


def test_the_policy_reuses_the_librarys_retryability_classifier() -> None:
    """The graph answers 'may this be retried?' with the same classifier every other caller does."""
    assert GraphPolicy.retryable is is_retryable_failure


async def test_a_query_is_never_rebuilt_between_attempts() -> None:
    """The statement object is the same one, so a retry cannot carry a different scope."""
    runner = _Runner(failures=1)
    query = _query()
    await GraphPolicy(max_attempts=2).run(runner, query=query, context=graph_context())
    assert [seen for seen, _ in runner.calls] == [query, query]
