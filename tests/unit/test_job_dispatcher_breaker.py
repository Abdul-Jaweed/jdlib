"""The dispatcher consults the breaker, so a dead dependency stops being retried.

The reliability inventory recorded the last of its seven gaps as *closed but unadopted*: the
breaker exists, the connector consults it, and nothing else did - so a job whose dependency was
down was retried for as long as the budget allowed, on every delivery, forever. This is the
adoption, and it is deliberately opt-in: a dispatcher constructed without a breaker behaves
exactly as before, which is what keeps every existing deployment unchanged.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from jdlib.config import ContextConfig
from jdlib.context import EnvelopeCodec, Principal, PrincipalKind, TenantContext, TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.reliability import BreakerPolicy, BreakerState, CircuitBreaker
from jdlib.tenancy.dead_letter import InMemoryDeadLetterStore
from jdlib.tenancy.job_envelope import (
    JobAttemptsExhaustedError,
    JobDispatcher,
    JobEnvelope,
    JobRetry,
)
from jdlib.tenancy.jobs import ContextPropagator
from tests.support.context_fakes import (
    DictTenants,
    EntitlementsStub,
    FrozenClock,
    ServabilityStub,
    StaticPrincipals,
)

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
PRINCIPAL_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")
KEY = "job-breaker-test-key"
START = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
LIFETIME = timedelta(minutes=5)


class TransientFailure(RuntimeError):
    """A failure the taxonomy calls retryable, whatever its message says."""

    transient = True


async def _no_sleep(_seconds: float) -> None:
    return None


def _no_jitter(_low: float, _high: float) -> float:
    return 0.0


class _World:
    def __init__(self) -> None:
        self.clock = FrozenClock(START)
        self.active = {PRINCIPAL_ID}
        self.record = TenantRecord(
            id=TENANT_ID,
            slug="acme",
            status=TenantStatus.ACTIVE,
            strategy=PlacementStrategy.SHARED,
        )
        self.dead_letters = InMemoryDeadLetterStore()
        self.seen: set[str] = set()

    def codec(self) -> EnvelopeCodec:
        return EnvelopeCodec(
            config=ContextConfig(signing_key=KEY, envelope_ttl=LIFETIME), clock=self.clock
        )

    def propagator(self) -> ContextPropagator:
        return ContextPropagator(
            codec=self.codec(),
            principals=StaticPrincipals(self.active),
            tenants=DictTenants([self.record]),
            servability=ServabilityStub(suspended=set(), records={TENANT_ID: self.record}),
            entitlements=EntitlementsStub({(PRINCIPAL_ID, TENANT_ID)}),
        )

    def dispatcher(self, **overrides: object) -> JobDispatcher:
        return JobDispatcher(
            propagator=self.propagator(),
            key=KEY,
            clock=self.clock,
            seen=self.seen,
            dead_letters=self.dead_letters,
            sleeper=_no_sleep,
            jitter=_no_jitter,
            **overrides,  # type: ignore[arg-type]
        )

    def issue(self, job_id: str) -> str:
        return JobEnvelope.issue(
            codec=self.codec(),
            context=TenantContext(
                tenant_id=TENANT_ID,
                tenant_slug="acme",
                strategy=PlacementStrategy.SHARED,
                principal=Principal(kind=PrincipalKind.SERVICE_ACCOUNT, id=PRINCIPAL_ID),
                request_id="req-1",
                correlation_id="corr-1",
                trace_id=None,
            ),
            job_id=job_id,
            ttl=LIFETIME,
            key=KEY,
            clock=self.clock,
        ).to_token()


class Handler:
    def __init__(self, *, failures: int) -> None:
        self.calls = 0
        self.failures = failures

    async def __call__(self) -> str:
        self.calls += 1
        if self.calls <= self.failures:
            raise TransientFailure("the dependency is unwell")
        return "done"


def _breaker(world: _World, *, threshold: int, reset_after: timedelta) -> CircuitBreaker:
    return CircuitBreaker(
        policy=BreakerPolicy(failure_threshold=threshold, reset_after=reset_after),
        clock=world.clock.now,
    )


@pytest.mark.asyncio
async def test_an_open_circuit_stops_the_dispatcher_before_the_handler_runs() -> None:
    """Once the dependency's failure tripped the circuit, a new job is not even attempted."""
    world = _World()
    breaker = _breaker(world, threshold=1, reset_after=timedelta(seconds=30))
    dispatcher = world.dispatcher(breaker=breaker)

    first = Handler(failures=99)
    with pytest.raises(TransientFailure):
        await dispatcher.execute(world.issue("job-0001"), first)
    assert breaker.is_open, "one failure at a threshold of one must open the circuit"
    assert first.calls == 1

    second = Handler(failures=0)
    with pytest.raises(JobAttemptsExhaustedError, match="circuit"):
        await dispatcher.execute(world.issue("job-0002"), second)
    assert second.calls == 0, "an open circuit must refuse the job before the handler runs"

    rows = world.dead_letters.entries()
    assert any(
        row.reason == "breaker" and row.error_type == "CircuitBreakerOpen" for row in rows
    ), (
        "the refusal is a decision the dispatcher made, so it is written down"
    )


@pytest.mark.asyncio
async def test_a_successful_attempt_closes_the_circuit_again() -> None:
    world = _World()
    breaker = _breaker(world, threshold=2, reset_after=timedelta(seconds=30))
    dispatcher = world.dispatcher(breaker=breaker, retry=JobRetry(max_attempts=2))

    assert await dispatcher.execute(world.issue("job-0001"), Handler(failures=1)) == "done"
    assert breaker.state is BreakerState.CLOSED, "the dependency answered, so the count resets"
    assert breaker.allow()


@pytest.mark.asyncio
async def test_a_failed_half_open_trial_reopens_the_circuit() -> None:
    world = _World()
    breaker = _breaker(world, threshold=1, reset_after=timedelta(seconds=30))
    dispatcher = world.dispatcher(breaker=breaker)

    with pytest.raises(TransientFailure):
        await dispatcher.execute(world.issue("job-0001"), Handler(failures=99))
    assert breaker.is_open

    world.clock.advance(timedelta(seconds=31))
    assert await dispatcher.execute(world.issue("job-0002"), Handler(failures=0)) == "done"
    assert breaker.state is BreakerState.CLOSED


@pytest.mark.asyncio
async def test_without_a_breaker_nothing_changes() -> None:
    """The adoption is opt-in: no breaker, no consultation, no extra records."""
    world = _World()
    dispatcher = world.dispatcher()
    handler = Handler(failures=99)

    with pytest.raises(TransientFailure):
        await dispatcher.execute(world.issue("job-0001"), handler)
    assert handler.calls == 1
    assert world.dead_letters.entries() == (), (
        "a single-attempt dispatcher decides nothing, so it records nothing"
    )
