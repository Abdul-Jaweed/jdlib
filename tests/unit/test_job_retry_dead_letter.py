"""Job retries and dead letters: the three absences the inventory named, in one place.

It recorded that a job had no retry budget, that a worker had no retry policy of its own, and
that a job which failed for good was nowhere - it simply stopped existing. The failure mode is
the quiet one: a job that is never retried and never recorded looks exactly like a job that was
never enqueued, and nothing downstream can tell the difference.

So the tests come in pairs. A transient failure is retried and can succeed; a permanent one is
not retried and is recorded. Attempts running out is a decision and is recorded; a failure the
handler raised under a single-attempt configuration is neither, and is re-raised untouched, which
is what keeps this change invisible to every deployment that did not ask for retries.

The security half is the part worth reading twice: an attempt revalidates its authority, so a
tenant suspended between two attempts stops the job instead of running it again, and the record
keeps the error's *type* and never its message.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from jdlib.config import ContextConfig
from jdlib.context import EnvelopeCodec, Principal, PrincipalKind, TenantContext, TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.errors import TenantSuspended
from jdlib.reliability import RetryBudget
from jdlib.tenancy.dead_letter import InMemoryDeadLetterStore
from jdlib.tenancy.job_envelope import (
    EnvelopeExpiredError,
    EnvelopeForgeryError,
    EnvelopeReplayError,
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
KEY = "job-retry-test-key"
START = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
LIFETIME = timedelta(minutes=5)


class TransientFailure(RuntimeError):
    """A failure the taxonomy calls retryable, whatever its message says."""

    transient = True


class PermanentFailure(RuntimeError):
    """A failure nothing should retry."""


async def _no_sleep(_seconds: float) -> None:
    return None


def _no_jitter(_low: float, _high: float) -> float:
    return 0.0


class _World:
    """The stubs a dispatcher needs, wired to the fakes the envelope tests already use."""

    def __init__(self, *, key: str = KEY) -> None:
        self.key = key
        self.clock = FrozenClock(START)
        self.active = {PRINCIPAL_ID}
        self.suspended: set[uuid.UUID] = set()
        self.record = TenantRecord(
            id=TENANT_ID,
            slug="acme",
            status=TenantStatus.ACTIVE,
            strategy=PlacementStrategy.SHARED,
        )
        self.dead_letters = InMemoryDeadLetterStore()

    def codec(self) -> EnvelopeCodec:
        return EnvelopeCodec(
            config=ContextConfig(signing_key=self.key, envelope_ttl=LIFETIME), clock=self.clock
        )

    def propagator(self) -> ContextPropagator:
        return ContextPropagator(
            codec=self.codec(),
            principals=StaticPrincipals(self.active),
            tenants=DictTenants([self.record]),
            servability=ServabilityStub(suspended=self.suspended, records={TENANT_ID: self.record}),
            entitlements=EntitlementsStub({(PRINCIPAL_ID, TENANT_ID)}),
        )

    def dispatcher(self, **overrides: object) -> JobDispatcher:
        return JobDispatcher(
            propagator=overrides.pop("propagator", self.propagator()),
            key=KEY,
            clock=self.clock,
            seen=overrides.pop("seen", set()),
            dead_letters=self.dead_letters,
            sleeper=_no_sleep,
            jitter=_no_jitter,
            **overrides,  # type: ignore[arg-type]
        )

    def issue(self, job_id: str = "job-0001") -> str:
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
            key=self.key,
            clock=self.clock,
        ).to_token()


class Handler:
    """A handler that fails a given number of times before it succeeds."""

    def __init__(self, *, failures: int, error: Exception | None = None) -> None:
        self.calls = 0
        self.failures = failures
        self.error = error if error is not None else TransientFailure("the dependency is unwell")

    async def __call__(self) -> str:
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error
        return "done"


async def test_a_transient_failure_is_retried_and_can_succeed() -> None:
    world = _World()
    handler = Handler(failures=1)

    result = await world.dispatcher(retry=JobRetry(max_attempts=3)).execute(
        world.issue(), handler
    )

    assert result == "done"
    assert handler.calls == 2
    assert len(world.dead_letters) == 0, "a job that worked is not a dead letter"


async def test_running_out_of_attempts_dead_letters_the_job() -> None:
    world = _World()
    handler = Handler(failures=9)

    with pytest.raises(JobAttemptsExhaustedError) as caught:
        await world.dispatcher(retry=JobRetry(max_attempts=3)).execute(world.issue(), handler)

    assert handler.calls == 3
    assert isinstance(caught.value.__cause__, TransientFailure), (
        "the give-up must carry the failure it gave up on"
    )
    entries = world.dead_letters.entries()
    assert len(entries) == 1
    assert entries[0].job_id == "job-0001"
    assert entries[0].tenant_id == TENANT_ID
    assert entries[0].attempts == 3
    assert entries[0].reason == "exhausted"
    assert entries[0].error_type == "TransientFailure"


async def test_a_permanent_failure_is_not_retried_and_is_recorded() -> None:
    world = _World()
    handler = Handler(failures=9, error=PermanentFailure("this will never work"))

    with pytest.raises(PermanentFailure):
        await world.dispatcher(retry=JobRetry(max_attempts=3)).execute(world.issue(), handler)

    assert handler.calls == 1, "a failure that says do not retry it is not retried"
    entries = world.dead_letters.entries()
    assert len(entries) == 1 and entries[0].reason == "permanent"


async def test_the_record_keeps_the_error_type_and_never_its_message() -> None:
    """A driver's message quotes the statement; a handler's can quote the payload."""
    world = _World()
    marker = "SECRET-MARKER-1234"
    handler = Handler(failures=9, error=TransientFailure(f"failed for {marker}: select * from x"))

    with pytest.raises(JobAttemptsExhaustedError):
        await world.dispatcher(retry=JobRetry(max_attempts=2)).execute(world.issue(), handler)

    rendered = repr(world.dead_letters.entries())
    assert marker not in rendered, "the message is not evidence and must not be kept"
    assert "TransientFailure" in rendered, "the type is the part that is"


async def test_authority_withdrawn_between_attempts_stops_the_job() -> None:
    """The retry is a new execution of the same authority, so it is validated again."""
    world = _World()
    handler = Handler(failures=9)
    dispatcher = world.dispatcher(retry=JobRetry(max_attempts=4))
    wire = world.issue()

    async def suspend_after_the_first_failure(*_args: object, **_kwargs: object) -> None:
        world.suspended.add(TENANT_ID)

    original = world.propagator().reconstruct

    class _SuspendsAfterOneFailure:
        def __init__(self) -> None:
            self.calls = 0

        async def reconstruct(self, token: str) -> TenantContext:
            self.calls += 1
            if self.calls > 1:
                world.suspended.add(TENANT_ID)
            return await original(token)

    dispatcher = JobDispatcher(
        propagator=_SuspendsAfterOneFailure(),  # type: ignore[arg-type]
        key=KEY,
        clock=world.clock,
        seen=set(),
        dead_letters=world.dead_letters,
        sleeper=_no_sleep,
        jitter=_no_jitter,
        retry=JobRetry(max_attempts=4),
    )

    with pytest.raises(TenantSuspended):
        await dispatcher.execute(wire, handler)

    assert handler.calls == 1, "the second attempt never reached the handler"
    entries = world.dead_letters.entries()
    assert len(entries) == 1
    assert entries[0].reason == "refused"
    assert entries[0].error_type == "TenantSuspended"
    assert entries[0].attempts == 2


async def test_a_job_whose_lifetime_lapses_between_attempts_stops() -> None:
    world = _World()
    wire = world.issue()

    class _LapsesAfterTheFirstAttempt(Handler):
        async def __call__(self) -> str:
            world.clock.advance(LIFETIME + timedelta(seconds=1))
            return await super().__call__()

    lapsing = _LapsesAfterTheFirstAttempt(failures=9)

    with pytest.raises(EnvelopeExpiredError):
        await world.dispatcher(retry=JobRetry(max_attempts=4)).execute(wire, lapsing)

    assert lapsing.calls == 1
    entries = world.dead_letters.entries()
    assert len(entries) == 1 and entries[0].reason == "refused"


async def test_a_spent_retry_budget_stops_the_job_and_says_so() -> None:
    world = _World()
    handler = Handler(failures=9)
    budget = RetryBudget(capacity=1, refill_per_second=0.0)

    with pytest.raises(JobAttemptsExhaustedError, match="budget is spent"):
        await world.dispatcher(retry=JobRetry(max_attempts=5), retry_budget=budget).execute(
            world.issue(), handler
        )

    assert handler.calls == 2, "one attempt, one retry, then the budget said no more"
    entries = world.dead_letters.entries()
    assert len(entries) == 1 and entries[0].reason == "budget"


async def test_a_retry_is_not_a_replay_but_a_second_delivery_is() -> None:
    world = _World()
    dispatcher = world.dispatcher(retry=JobRetry(max_attempts=3))
    wire = world.issue()

    assert await dispatcher.execute(wire, Handler(failures=1)) == "done"

    with pytest.raises(EnvelopeReplayError):
        await dispatcher.execute(wire, Handler(failures=0))


async def test_a_forged_envelope_is_refused_and_never_recorded() -> None:
    """Anything that can put bytes on a queue could otherwise fill the store with junk."""
    world = _World()
    # Signed with a key this dispatcher does not hold: unreadable to it, which is the attack.
    wire = _World(key="some-other-signing-key").issue()

    with pytest.raises(EnvelopeForgeryError):
        await world.dispatcher(retry=JobRetry(max_attempts=3)).execute(wire, Handler(failures=0))

    assert len(world.dead_letters) == 0


async def test_a_single_attempt_configuration_changes_nothing() -> None:
    """The default: no retry, no record, and the handler's own error raised unchanged."""
    world = _World()
    handler = Handler(failures=9)
    error = TransientFailure("exactly what the handler raised")

    with pytest.raises(TransientFailure) as caught:
        await world.dispatcher().execute(world.issue(), Handler(failures=9, error=error))

    assert handler.calls == 0
    assert caught.value is error
    assert len(world.dead_letters) == 0, "nothing was decided here, so nothing is recorded"


async def test_dead_letters_are_readable_under_one_tenant() -> None:
    world = _World()
    store = world.dead_letters
    dispatcher = world.dispatcher(retry=JobRetry(max_attempts=2))

    with pytest.raises(JobAttemptsExhaustedError):
        await dispatcher.execute(world.issue("job-0001"), Handler(failures=9))

    with pytest.raises(JobAttemptsExhaustedError):
        await dispatcher.execute(world.issue("job-0002"), Handler(failures=9))

    assert len(store.entries()) == 2
    assert len(store.entries(tenant_id=TENANT_ID)) == 2
    assert store.entries(tenant_id=uuid.uuid4()) == (), "another tenant reads none of it"
