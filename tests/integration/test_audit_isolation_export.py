"""Layer 2: audit authorization, isolation and export against real PostgreSQL.

The unit tests prove the capability model and the renderers. These prove the part
only a database can answer:

* a tenant reader sees its own tenant's trail and nothing else, no matter what
  the query asks for,
* asking for another tenant's rows is refused unless the caller holds the
  platform capability — and only then does it work,
* a scope-less caller is refused before any SQL runs,
* pagination is stable (no repeats, no gaps, deterministic order),
* an export is byte-identical across calls, bounded, and recorded as its own
  event,
* the export path cannot leak a secret that was stored before the metadata rules
  existed.
"""

from __future__ import annotations

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
from jdlib.security.audit import (
    AuditAccess,
    AuditOutcome,
    AuditQuery,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
    export_events,
    read_events,
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
MAX_LIMIT_FOR_TEST = 200

TENANT_READER = AuditAccess(scopes=frozenset({"audit.read.tenant"}))
PLATFORM_READER = AuditAccess(scopes=frozenset({"audit.read.platform"}), platform_operator=True)
EXPORTER = AuditAccess(scopes=frozenset({"audit.read.tenant", "audit.export"}))
WRITER_ONLY = AuditAccess(scopes=frozenset({"audit.write"}))
ANONYMOUS = AuditAccess(scopes=None)


@contextmanager
def _request(tenant_id: uuid.UUID, *, request_id: str = "req-1") -> Iterator[None]:
    principal = Principal(id=PRINCIPAL, kind=PrincipalKind.USER)
    request_ids = RequestIds(request_id=request_id, correlation_id="corr-1")
    tenant = TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id=request_id,
        correlation_id="corr-1",
    )
    security = SecurityContext(
        principal=principal,
        request_ids=request_ids,
        auth_method=AuthMethod.SERVICE,
        tenant=tenant,
    )
    with context_scope(tenant), security_context_scope(security):
        yield


@asynccontextmanager
async def _session(session_factory) -> AsyncIterator[object]:
    async with session_factory() as session:
        await session.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
        yield session


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    async def emit(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)


async def _seed(session_factory, tenant_id: uuid.UUID, *, count: int, prefix: str) -> None:
    with _request(tenant_id, request_id=f"{prefix}-seed"):
        async with _session(session_factory) as session:
            recorder = TenantAuditRecorder(session)
            for index in range(count):
                recorder.record_security(
                    SecurityAuditEvent(
                        event_type=SecurityEventType.AUTHZ_DENY,
                        outcome=AuditOutcome.DENIED,
                        action=f"{prefix}-{index}",
                        source=AuditSource.API,
                        resource_type="document",
                        resource_id="doc-42",
                        request_id=f"{prefix}-req-{index}",
                        metadata={"index": index},
                    )
                )
            await session.commit()


async def test_a_tenant_reader_sees_only_its_own_tenant(session_factory) -> None:
    await _seed(session_factory, TENANT_A, count=3, prefix="a")
    await _seed(session_factory, TENANT_B, count=2, prefix="b")

    async with _session(session_factory) as session:
        page = await read_events(session, access=TENANT_READER, tenant_id=TENANT_A)
    assert page.events, "expected the seeded events"
    assert {event.tenant_id for event in page.events} == {TENANT_A}
    assert {"a-0", "a-1", "a-2"} <= {event.action for event in page.events}


async def test_asking_for_another_tenant_is_refused_for_a_tenant_reader(session_factory) -> None:
    await _seed(session_factory, TENANT_B, count=1, prefix="b2")
    from jdlib.errors import PermissionDenied

    async with _session(session_factory) as session:
        with pytest.raises(PermissionDenied):
            await read_events(
                session,
                access=TENANT_READER,
                tenant_id=TENANT_A,
                query=AuditQuery(tenant_id=TENANT_B),
            )


async def test_a_platform_reader_can_read_another_tenant(session_factory) -> None:
    await _seed(session_factory, TENANT_B, count=2, prefix="b3")
    async with _session(session_factory) as session:
        page = await read_events(
            session,
            access=PLATFORM_READER,
            tenant_id=TENANT_A,
            query=AuditQuery(tenant_id=TENANT_B),
        )
    assert page.events
    assert {event.tenant_id for event in page.events} == {TENANT_B}


async def test_a_scope_less_caller_is_refused(session_factory) -> None:
    from jdlib.errors import AuthenticationError

    async with _session(session_factory) as session:
        with pytest.raises(AuthenticationError):
            await read_events(session, access=ANONYMOUS, tenant_id=TENANT_A)


async def test_writing_the_trail_does_not_allow_reading_it(session_factory) -> None:
    from jdlib.errors import PermissionDenied

    async with _session(session_factory) as session:
        with pytest.raises(PermissionDenied):
            await read_events(session, access=WRITER_ONLY, tenant_id=TENANT_A)


async def test_pagination_is_stable_and_complete(session_factory) -> None:
    await _seed(session_factory, TENANT_A, count=7, prefix="page")
    seen: list[str] = []
    offset: int | None = 0
    async with _session(session_factory) as session:
        while offset is not None:
            page = await read_events(
                session,
                access=TENANT_READER,
                tenant_id=TENANT_A,
                query=AuditQuery(limit=3, offset=offset),
            )
            seen.extend(event.action for event in page.events)
            offset = page.next_offset
    assert len(seen) == len(set(seen)), "pagination must not repeat rows"
    assert {"page-0", "page-6"} <= set(seen)


async def test_export_is_deterministic_and_bounded(session_factory) -> None:
    await _seed(session_factory, TENANT_A, count=4, prefix="exp")
    sink = _RecordingSink()
    async with _session(session_factory) as session:
        first = await export_events(
            session, access=EXPORTER, tenant_id=TENANT_A, fmt="json", on_export=sink
        )
        second = await export_events(
            session, access=EXPORTER, tenant_id=TENANT_A, fmt="json", on_export=sink
        )
    assert first == second, "the same query must render byte-identically"
    records = json.loads(first)
    assert all(record["tenant_id"] == str(TENANT_A) for record in records)
    assert len(records) <= 100  # default bound
    # the export itself is audited
    assert [event.event_type for event in sink.events] == [
        SecurityEventType.AUDIT_EXPORTED,
        SecurityEventType.AUDIT_EXPORTED,
    ]
    assert sink.events[0].tenant_id == TENANT_A
    assert sink.events[0].metadata["format"] == "json"


async def test_every_rendering_of_the_same_page_agrees(session_factory) -> None:
    await _seed(session_factory, TENANT_A, count=2, prefix="fmt")
    async with _session(session_factory) as session:
        rendered = {
            fmt: await export_events(session, access=EXPORTER, tenant_id=TENANT_A, fmt=fmt)
            for fmt in ("json", "jsonl", "csv")
        }
    from_json = json.loads(rendered["json"])
    from_jsonl = [json.loads(line) for line in rendered["jsonl"].splitlines()]
    assert [record["event_id"] for record in from_json] == [
        record["event_id"] for record in from_jsonl
    ]
    assert rendered["csv"].splitlines()[0].startswith("event_id,")
    assert len(rendered["csv"].splitlines()) == len(from_json) + 1


async def test_an_export_cannot_leak_a_row_written_outside_the_current_rules(
    session_factory,
) -> None:
    # A row carrying metadata the current rules would refuse must not leak via
    # the export path: it is re-sanitized on the way out.
    row = AuditEvent(
        tenant_id=TENANT_A,
        actor_type="user",
        actor_id=PRINCIPAL,
        action="legacy",
        event_type="CREDENTIAL_ROTATED",
        outcome="SUCCESS",
        source="API",
        metadata_json={
            "dsn": "postgresql+asyncpg://app:s3cr3t-pw@db.internal:5432/jdlib",
            "bad key": "value",
            "nested": {"a": 1},
        },
    )
    async with _session(session_factory) as session:
        session.add(row)
        await session.commit()

    async with _session(session_factory) as session:
        exported = await export_events(
            session,
            access=EXPORTER,
            tenant_id=TENANT_A,
            query=AuditQuery(request_id=None, limit=MAX_LIMIT_FOR_TEST),
        )
    assert "s3cr3t-pw" not in exported
    assert "bad key" not in exported


async def test_export_requires_the_export_capability(session_factory) -> None:
    from jdlib.errors import PermissionDenied

    async with _session(session_factory) as session:
        with pytest.raises(PermissionDenied):
            await export_events(session, access=TENANT_READER, tenant_id=TENANT_A)


async def test_unsupported_format_is_refused_before_reading(session_factory) -> None:
    async with _session(session_factory) as session:
        with pytest.raises(ValueError, match="unsupported export format"):
            await export_events(
                session,
                access=AuditAccess(scopes=frozenset({"audit.export"})),
                tenant_id=TENANT_A,
                fmt="xml",
            )
