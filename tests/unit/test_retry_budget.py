"""Cross-call limits, and the context a retry must run under.

The reliability inventory recorded both of these as ABSENT. `max_attempts` bounded one call and
nothing bounded retries *across* calls - the amplification problem, where every caller retrying
three times multiplies the load on a dependency that is already failing. And no code stated what
has to survive a retry, which is quieter and worse: a retry that runs without the context the
original call had is a retry that can reach another tenant's rows.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.data.errors import ConnectorError
from jdlib.data.policy import ConnectionPolicy
from jdlib.reliability import RetryBudget, RetryBudgetExhaustedError
from jdlib.security.context import (
    AuthMethod,
    SecurityContext,
    current_security_context_or_none,
    security_context_scope,
)


class _AlwaysFails:
    """A connector that fails every attempt, remembering the context it saw."""

    def __init__(self, *, drop_context: bool = False) -> None:
        self.attempts = 0
        self.seen: list[SecurityContext | None] = []
        self._drop = drop_context

    async def execute(
        self, *, statement: str, params: tuple[Any, ...] = ()
    ) -> list[dict[str, Any]]:
        self.attempts += 1
        self.seen.append(current_security_context_or_none())
        if self._drop:
            # A boundary that lost the context: a thread, a spawned task, a queue hop. The
            # policy has to put it back for the next attempt rather than hope it survived.
            # Reaching for the module's own ContextVar is the only way to simulate that loss,
            # and it is private on purpose - nothing outside this file should do it.
            from jdlib.security.context import _SECURITY_CONTEXT

            _SECURITY_CONTEXT.set(None)
        raise ConnectorError("the dependency is refusing connections", transient=True)


class _SucceedsOnSecondAttempt(_AlwaysFails):
    async def execute(
        self, *, statement: str, params: tuple[Any, ...] = ()
    ) -> list[dict[str, Any]]:
        self.attempts += 1
        self.seen.append(current_security_context_or_none())
        if self.attempts == 1:
            raise ConnectorError("the dependency is refusing connections", transient=True)
        return [{"ok": True}]


def _context() -> SecurityContext:
    tenant = TenantContext(
        tenant_id=uuid.uuid4(),
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req-1",
        correlation_id="corr-1",
        trace_id=None,
    )
    return SecurityContext.from_tenant_context(tenant=tenant, auth_method=AuthMethod.SERVICE)


async def _no_sleep(_seconds: float) -> None:
    return None


def test_a_budget_refuses_what_it_has_no_tokens_for() -> None:
    budget = RetryBudget(capacity=2, refill_per_second=0.0)
    now = datetime(2026, 9, 25, tzinfo=UTC)

    assert budget.take(now=now) is True
    assert budget.take(now=now) is True
    assert budget.take(now=now) is False, "the third retry is the one the budget exists to refuse"
    assert budget.available(now=now) == 0


def test_tokens_refill_over_time() -> None:
    budget = RetryBudget(capacity=1, refill_per_second=0.5)
    now = datetime(2026, 9, 25, tzinfo=UTC)

    assert budget.take(now=now) is True
    assert budget.take(now=now) is False
    assert budget.take(now=now + timedelta(seconds=2)) is True, "a recovered dependency recovers"
    assert budget.available(now=now + timedelta(seconds=2)) == 0


async def test_the_first_attempt_does_not_consume_a_token() -> None:
    """A budget limits retries. A limiter that also refuses the first attempt is a rate limit."""
    budget = RetryBudget(capacity=1, refill_per_second=0.0)
    policy = ConnectionPolicy(max_attempts=1, retry_budget=budget)

    with pytest.raises(ConnectorError):
        await policy.run(_AlwaysFails(), statement="select 1", sleeper=_no_sleep)

    assert budget.available(now=datetime(2026, 9, 25, tzinfo=UTC)) == 1


async def test_a_policy_stops_retrying_when_the_budget_is_spent() -> None:
    budget = RetryBudget(capacity=1, refill_per_second=0.0)
    policy = ConnectionPolicy(max_attempts=3, retry_budget=budget)
    connector = _AlwaysFails()

    with pytest.raises(RetryBudgetExhaustedError) as caught:
        await policy.run(connector, statement="select 1", sleeper=_no_sleep)

    # The first attempt plus exactly one retry: the second retry had no token.
    assert connector.attempts == 2
    assert isinstance(caught.value.__cause__, ConnectorError), (
        "the refusal must carry the failure it declined to retry"
    )


async def test_a_retry_runs_under_the_context_the_call_started_with() -> None:
    context = _context()
    connector = _SucceedsOnSecondAttempt()

    with security_context_scope(context):
        result = await ConnectionPolicy(max_attempts=2).run(
            connector, statement="select 1", sleeper=_no_sleep
        )

    assert result == [{"ok": True}]
    assert connector.seen == [context, context], (
        "every attempt must see the calling context, including the one after a boundary dropped it"
    )


async def test_a_retry_restores_the_context_a_boundary_dropped() -> None:
    context = _context()
    connector = _AlwaysFails(drop_context=True)
    policy = ConnectionPolicy(max_attempts=2)

    with security_context_scope(context), pytest.raises(ConnectorError):
        await policy.run(connector, statement="select 1", sleeper=_no_sleep)

    assert connector.seen == [context, context], (
        "the second attempt ran after the first attempt cleared the ambient context, so it can "
        "only have seen it because the policy re-established it"
    )


async def test_a_retry_without_a_calling_context_does_not_invent_one() -> None:
    connector = _SucceedsOnSecondAttempt()

    result = await ConnectionPolicy(max_attempts=2).run(
        connector, statement="select 1", sleeper=_no_sleep
    )

    assert result == [{"ok": True}]
    assert connector.seen == [None, None], (
        "no context in, no context invented: the refusals downstream depend on that"
    )
