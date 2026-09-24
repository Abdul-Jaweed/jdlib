"""Background job envelopes (successor Phase 10). RED first.

The tenant token, its signature, its TTL and its clock already exist: `EnvelopeCodec` signs a
`TenantContext` and refuses an expired one, and `ContextPropagator.reconstruct` already walks
the chain a job has to walk - principal active, tenant present, entitlement held, tenant
servable. None of that is rebuilt here, and this file uses the same fakes the existing envelope
tests use rather than inventing parallel ones.

What this phase adds is the job's own identity and the two things a queue needs that a request
does not: replay detection and revocation. A worker may run the same delivery twice, and a job
may wait in a queue while the authority behind it is withdrawn, so the envelope carries a job
id and its own lifetime, signed together with the tenant token.

The gate's attacks, one named test each: envelope forgery, TTL lapse, replay after revocation,
and tenant suspension between enqueue and execution.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from jdlib.config import ContextConfig
from jdlib.context import EnvelopeCodec, Principal, PrincipalKind, TenantContext, TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.errors import TenantSuspended, UnknownPrincipal
from jdlib.tenancy.job_envelope import (
    EnvelopeExpiredError,
    EnvelopeForgeryError,
    EnvelopeReplayError,
    JobDispatcher,
    JobEnvelope,
    JobEnvelopeError,
    JobRevokedError,
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
KEY = "job-envelope-test-key"
START = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)
LIFETIME = timedelta(minutes=5)


class _World:
    """The stubs a dispatcher needs, wired to the shared fakes."""

    def __init__(self) -> None:
        self.clock = FrozenClock(START)
        self.active = {PRINCIPAL_ID}
        self.suspended: set[uuid.UUID] = set()
        self.record = TenantRecord(
            id=TENANT_ID,
            slug="acme",
            status=TenantStatus.ACTIVE,
            strategy=PlacementStrategy.SHARED,
        )
        self.revoked: set[str] = set()

    def codec(self, ttl: timedelta = LIFETIME) -> EnvelopeCodec:
        return EnvelopeCodec(
            config=ContextConfig(signing_key=KEY, envelope_ttl=ttl), clock=self.clock
        )

    def propagator(self) -> ContextPropagator:
        return ContextPropagator(
            codec=self.codec(),
            principals=StaticPrincipals(self.active),
            tenants=DictTenants([self.record]),
            servability=ServabilityStub(suspended=self.suspended, records={TENANT_ID: self.record}),
            entitlements=EntitlementsStub({(PRINCIPAL_ID, TENANT_ID)}),
        )

    def dispatcher(self, **overrides) -> JobDispatcher:
        return JobDispatcher(
            propagator=overrides.pop("propagator", self.propagator()),
            key=overrides.pop("key", KEY),
            clock=self.clock,
            is_revoked=overrides.pop("is_revoked", lambda job_id: job_id in self.revoked),
            **overrides,
        )

    def issue(self, job_id: str = "job-0001", ttl: timedelta = LIFETIME) -> str:
        return JobEnvelope.issue(
            codec=self.codec(ttl),
            context=self.context(),
            job_id=job_id,
            ttl=ttl,
            key=KEY,
            clock=self.clock,
        ).to_token()

    @staticmethod
    def context() -> TenantContext:
        return TenantContext(
            tenant_id=TENANT_ID,
            tenant_slug="acme",
            strategy=PlacementStrategy.SHARED,
            principal=Principal(kind=PrincipalKind.SERVICE_ACCOUNT, id=PRINCIPAL_ID),
            request_id="req-1",
            correlation_id="corr-1",
            trace_id=None,
        )


async def _unreachable() -> str:  # pragma: no cover - reaching this fails the test
    raise AssertionError("the handler ran when the revalidation chain should have refused")


def _returns(value: str):
    async def handler() -> str:
        return value

    return handler


# --- the control: a valid envelope runs, inside its tenant context --------------------------


async def test_a_valid_envelope_runs_the_job_inside_its_tenant_context() -> None:
    from jdlib.context import current_tenant

    world = _World()
    seen: list[uuid.UUID] = []

    async def handler() -> str:
        seen.append(current_tenant().tenant_id)
        return "done"

    result = await world.dispatcher().execute(world.issue(), handler)

    assert result == "done"
    assert seen == [TENANT_ID]


# --- gate item 1: forgery -------------------------------------------------------------------


async def test_a_tampered_expiry_is_refused() -> None:
    """The signature covers the job's own fields, so a rewritten expiry invalidates it."""
    world = _World()
    envelope = JobEnvelope.parse(world.issue(), key=KEY)
    forged = JobEnvelope(
        job_id=envelope.job_id,
        token=envelope.token,
        issued_at=envelope.issued_at,
        expires_at=envelope.expires_at + timedelta(days=365),
        signature=envelope.signature,
    )

    with pytest.raises(EnvelopeForgeryError):
        await world.dispatcher().execute(forged.to_token(), _unreachable)


async def test_a_tampered_job_id_is_refused() -> None:
    """Swapping the identity is the forgery that matters: it would defeat replay detection."""
    world = _World()
    envelope = JobEnvelope.parse(world.issue("job-0001"), key=KEY)
    forged = JobEnvelope(
        job_id="job-9999",
        token=envelope.token,
        issued_at=envelope.issued_at,
        expires_at=envelope.expires_at,
        signature=envelope.signature,
    )

    with pytest.raises(EnvelopeForgeryError):
        await world.dispatcher().execute(forged.to_token(), _unreachable)


async def test_a_token_signed_with_another_key_is_refused() -> None:
    world = _World()
    foreign = JobEnvelope.issue(
        codec=world.codec(),
        context=world.context(),
        job_id="job-0001",
        ttl=LIFETIME,
        key="a-different-key",
        clock=world.clock,
    ).to_token()

    with pytest.raises(EnvelopeForgeryError):
        await world.dispatcher().execute(foreign, _unreachable)


@pytest.mark.parametrize("garbage", ["", "not-a-token", "....", "eyJhIjogMX0="])
async def test_a_malformed_token_is_refused(garbage: str) -> None:
    with pytest.raises(JobEnvelopeError):
        await _World().dispatcher().execute(garbage, _unreachable)


# --- gate item 2: TTL lapse -----------------------------------------------------------------


async def test_an_expired_envelope_is_refused() -> None:
    world = _World()
    token = world.issue()

    world.clock.advance(LIFETIME + timedelta(seconds=1))

    with pytest.raises(EnvelopeExpiredError):
        await world.dispatcher().execute(token, _unreachable)


# --- gate items 3 and 4: replay, revocation, suspension --------------------------------------


async def test_a_replayed_envelope_is_refused_the_second_time() -> None:
    world = _World()
    token = world.issue()
    dispatcher = world.dispatcher()

    assert await dispatcher.execute(token, _returns("first")) == "first"

    with pytest.raises(EnvelopeReplayError):
        await dispatcher.execute(token, _unreachable)


async def test_a_job_revoked_after_issue_is_refused() -> None:
    world = _World()
    token = world.issue()
    world.revoked.add("job-0001")

    with pytest.raises(JobRevokedError):
        await world.dispatcher().execute(token, _unreachable)


async def test_a_tenant_suspended_between_enqueue_and_execution_is_refused() -> None:
    """A queue is not a place where authority is frozen: it is re-checked at execution."""
    world = _World()
    token = world.issue()

    world.suspended.add(TENANT_ID)

    with pytest.raises(TenantSuspended):
        await world.dispatcher().execute(token, _unreachable)


async def test_a_principal_deactivated_between_enqueue_and_execution_is_refused() -> None:
    world = _World()
    token = world.issue()

    world.active.clear()

    with pytest.raises(UnknownPrincipal):
        await world.dispatcher().execute(token, _unreachable)


@pytest.mark.parametrize("failure", ["expired", "replayed", "revoked", "suspended", "principal"])
async def test_the_handler_never_runs_when_revalidation_fails(failure: str) -> None:
    """Fail closed means the work does not happen, not that an error was reported afterwards."""
    world = _World()
    token = world.issue()
    dispatcher = world.dispatcher()
    if failure == "expired":
        world.clock.advance(LIFETIME + timedelta(seconds=1))
    if failure == "replayed":
        await dispatcher.execute(token, _returns("first"))
    if failure == "revoked":
        world.revoked.add("job-0001")
    if failure == "suspended":
        world.suspended.add(TENANT_ID)
    if failure == "principal":
        world.active.clear()
    calls: list[str] = []

    async def watcher() -> str:
        calls.append("ran")
        return "ran"

    with pytest.raises((JobEnvelopeError, TenantSuspended, UnknownPrincipal)):
        await dispatcher.execute(token, watcher)

    assert calls == []


# --- issuing is validated too ---------------------------------------------------------------


def test_a_job_id_is_required_because_replay_cannot_be_detected_without_one() -> None:
    world = _World()

    for empty in ("", "   "):
        with pytest.raises(JobEnvelopeError):
            JobEnvelope.issue(
                codec=world.codec(),
                context=world.context(),
                job_id=empty,
                ttl=LIFETIME,
                key=KEY,
                clock=world.clock,
            )


def test_a_non_positive_lifetime_is_refused() -> None:
    world = _World()

    with pytest.raises(JobEnvelopeError):
        JobEnvelope.issue(
            codec=world.codec(),
            context=world.context(),
            job_id="job-0001",
            ttl=timedelta(0),
            key=KEY,
            clock=world.clock,
        )


async def test_distinct_jobs_are_not_replays_of_one_another() -> None:
    """Replay detection keys on the job id, not on the tenant: two jobs both run."""
    world = _World()
    dispatcher = world.dispatcher()

    first = await dispatcher.execute(world.issue("job-a"), _returns("a"))
    second = await dispatcher.execute(world.issue("job-b"), _returns("b"))

    assert (first, second) == ("a", "b")
