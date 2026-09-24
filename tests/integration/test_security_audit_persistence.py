"""Layer 2: security audit persistence against a real PostgreSQL (directive §5).

Mocked sinks prove nothing about durability, transaction semantics or isolation,
so everything here runs against the Testcontainers PostgreSQL the rest of the
integration suite uses.

What is proven, not assumed:

* a security event round-trips with every field intact,
* audit writes **participate in the caller's transaction** — that is the
  documented semantic: a rolled-back operation leaves no audit row, and an audit
  row is never written outside the operation it describes,
* concurrent writers do not lose events or collide on ids,
* a secret cannot be smuggled into stored metadata,
* an event that claims a tenant other than the ambient one is refused outright,
* the audit table is covered by the row-level-security policy generator, i.e.
  audit rows are not exempt from tenant isolation.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager

import pytest
import sqlalchemy as sa

from jdlib.context import Principal, PrincipalKind, TenantContext, context_scope
from jdlib.control.enums import PlacementStrategy
from jdlib.models.audit import AuditEvent
from jdlib.models.audit_recorder import TenantAuditRecorder
from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.rls import rls_eligible_tables
from jdlib.security.audit import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.context import (
    AuthMethod,
    RequestIds,
    SecurityContext,
    security_context_scope,
)
from tests.integration.conftest import TENANT_SCHEMA

pytestmark = pytest.mark.integration

TENANT_A = uuid.UUID("aaaaaaaa-1111-2222-3333-444444444444")
TENANT_B = uuid.UUID("bbbbbbbb-1111-2222-3333-444444444444")
PRINCIPAL = uuid.UUID("99999999-8888-7777-6666-555555555555")


@contextmanager
def _request(
    tenant_id: uuid.UUID,
    *,
    request_id: str = "req-1",
    principal_kind: PrincipalKind = PrincipalKind.USER,
    principal_id: uuid.UUID | None = PRINCIPAL,
) -> Iterator[None]:
    """Bind both contexts, as a real request does.

    The tenancy context routes the row (and satisfies RLS); the security context
    supplies the principal and the request/correlation/trace identifiers the
    envelope defaults to.
    """
    principal = Principal(id=principal_id, kind=principal_kind)
    request_ids = RequestIds(request_id=request_id, correlation_id="corr-1", trace_id="trace-1")
    tenant = TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id=request_id,
        correlation_id="corr-1",
        trace_id="trace-1",
    )
    security = (
        # An anonymous request binds the explicit unauthenticated context; it
        # carries no tenant, so the row's tenant still comes from the tenancy
        # context and the event's actor stays anonymous.
        SecurityContext.anonymous(request_ids=request_ids)
        if principal_kind is PrincipalKind.ANONYMOUS
        else SecurityContext(
            principal=principal,
            request_ids=request_ids,
            auth_method=AuthMethod.SERVICE,
            tenant=tenant,
        )
    )
    with context_scope(tenant), security_context_scope(security):
        yield


@asynccontextmanager
async def _session(session_factory) -> AsyncIterator[object]:
    # Each session sets its own search_path: the engine fixture sets it on one
    # pooled connection, which is not enough once sessions run concurrently.
    async with session_factory() as session:
        await session.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
        yield session


def _event(**overrides: object) -> SecurityAuditEvent:
    payload: dict[str, object] = {
        "event_type": SecurityEventType.AUTHZ_DENY,
        "outcome": AuditOutcome.DENIED,
        "action": "read",
        "source": AuditSource.API,
        "resource_type": "document",
        "resource_id": "doc-42",
    }
    payload.update(overrides)
    return SecurityAuditEvent(**payload)  # type: ignore[arg-type]


async def _count(session_factory, **filters: object) -> int:
    async with _session(session_factory) as session:
        query = sa.select(sa.func.count()).select_from(AuditEvent)
        for column, value in filters.items():
            query = query.where(getattr(AuditEvent, column) == value)
        return (await session.execute(query)).scalar_one()


async def _load(session_factory, event_id: uuid.UUID) -> AuditEvent:
    async with _session(session_factory) as session:
        return (
            await session.execute(sa.select(AuditEvent).where(AuditEvent.id == event_id))
        ).scalar_one()


async def test_security_event_round_trips_through_postgres(session_factory) -> None:
    with _request(TENANT_A):
        event = _event(metadata={"reason": "engine_unavailable", "duration_ms": 12})
        async with _session(session_factory) as session:
            TenantAuditRecorder(session).record_security(event)
            await session.commit()

    row = await _load(session_factory, event.event_id)
    assert row.tenant_id == TENANT_A
    assert row.event_type == "AUTHZ_DENY"
    assert row.outcome == "DENIED"
    assert row.source == "API"
    assert row.action == "read"
    assert row.target_type == "document"
    assert row.actor_id == PRINCIPAL
    assert row.actor_type == "user"
    assert row.request_id == "req-1"
    assert row.correlation_id == "corr-1"
    assert row.trace_id == "trace-1"
    assert row.metadata_json == {"reason": "engine_unavailable", "duration_ms": 12}


async def test_a_kind_outside_the_column_vocabulary_is_preserved_in_metadata(
    session_factory,
) -> None:
    # `anonymous` is a real principal kind but not a valid actor_type for the
    # audit table: the row must still be written, with the real kind preserved
    # in metadata rather than dropped. The actor has to be the one the request is
    # actually being made as (an event cannot rename its own actor — see phase 8
    # in docs/security/adversarial-review.md), so this records an event from an
    # anonymous request.
    with _request(TENANT_A, principal_kind=PrincipalKind.ANONYMOUS, principal_id=None):
        event = _event(principal_kind="anonymous")
        async with _session(session_factory) as session:
            TenantAuditRecorder(session).record_security(event)
            await session.commit()
    row = await _load(session_factory, event.event_id)
    assert row.actor_type == "system"
    assert row.metadata_json["principal_kind"] == "anonymous"


async def test_audit_write_participates_in_the_caller_transaction(session_factory) -> None:
    # Documented semantic: the audit row is written in the caller's transaction,
    # so a rolled-back operation audits nothing at all. An audit trail that
    # survived a rollback would describe work that never happened.
    with _request(TENANT_A):
        event = _event(event_type=SecurityEventType.TENANT_SUSPENDED, outcome=AuditOutcome.SUCCESS)
        async with _session(session_factory) as session:
            TenantAuditRecorder(session).record_security(event)
            await session.rollback()
    assert await _count(session_factory, id=event.event_id) == 0


async def test_committed_events_survive_and_are_counted(session_factory) -> None:
    with _request(TENANT_A):
        event = _event(
            event_type=SecurityEventType.CREDENTIAL_ROTATED, outcome=AuditOutcome.SUCCESS
        )
        async with _session(session_factory) as session:
            TenantAuditRecorder(session).record_security(event)
            await session.commit()
    assert await _count(session_factory, id=event.event_id) == 1


async def test_concurrent_writers_do_not_lose_or_collide(session_factory) -> None:
    events: list[SecurityAuditEvent] = []

    async def write(index: int) -> None:
        with _request(TENANT_A, request_id=f"req-{index}"):
            event = _event(metadata={"worker": index}, action=f"read-{index}")
            events.append(event)
            async with _session(session_factory) as session:
                TenantAuditRecorder(session).record_security(event)
                await session.commit()

    await asyncio.gather(*(write(index) for index in range(6)))

    assert len({event.event_id for event in events}) == 6
    async with _session(session_factory) as session:
        rows = (
            (
                await session.execute(
                    sa.select(AuditEvent.action).where(
                        AuditEvent.id.in_([event.event_id for event in events])
                    )
                )
            )
            .scalars()
            .all()
        )
    assert sorted(rows) == sorted(f"read-{index}" for index in range(6))


async def test_a_secret_cannot_reach_stored_metadata(session_factory) -> None:
    with _request(TENANT_A):
        event = _event(
            event_type=SecurityEventType.CREDENTIAL_CREATED,
            metadata={
                "dsn": "postgresql+asyncpg://jdlib_user:s3cr3t-pw@postgres.internal:5432/jdlib",
                "note": "token=abcdef123456789",
                "client_secret": "AbCdEf0123456789SecretValue",
                "reason": "rotation",
            },
        )
        async with _session(session_factory) as session:
            TenantAuditRecorder(session).record_security(event)
            await session.commit()

    row = await _load(session_factory, event.event_id)
    stored = json.dumps(row.metadata_json)
    for leak in ("s3cr3t-pw", "abcdef123456789", "AbCdEf0123456789SecretValue"):
        assert leak not in stored
    assert row.metadata_json["reason"] == "rotation"


async def test_an_event_claiming_another_tenant_is_refused(session_factory) -> None:
    # Fail closed: an audit row must never be attributed to a tenant other than
    # the one the caller is operating in.
    with _request(TENANT_A):
        event = _event(tenant_id=TENANT_B)
        async with _session(session_factory) as session:
            with pytest.raises(ValueError):
                TenantAuditRecorder(session).record_security(event)
    assert await _count(session_factory, id=event.event_id) == 0


async def test_tenant_rows_are_attributed_to_their_tenant(session_factory) -> None:
    for tenant_id in (TENANT_A, TENANT_B):
        with _request(tenant_id):
            event = _event(event_type=SecurityEventType.AUTHZ_ALLOW)
            async with _session(session_factory) as session:
                TenantAuditRecorder(session).record_security(event)
                await session.commit()
    async with _session(session_factory) as session:
        by_tenant = dict(
            (
                await session.execute(
                    sa.select(AuditEvent.tenant_id, sa.func.count())
                    .where(AuditEvent.tenant_id.in_([TENANT_A, TENANT_B]))
                    .group_by(AuditEvent.tenant_id)
                )
            ).all()
        )
    assert by_tenant[TENANT_A] >= 1
    assert by_tenant[TENANT_B] >= 1


def test_the_audit_table_is_covered_by_the_rls_policy_generator() -> None:
    # The RLS strategy derives its table list from the mapped classes; the audit
    # table must not be exempt from tenant isolation.
    assert "audit_events" in rls_eligible_tables(TenantBase.metadata)
