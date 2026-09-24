"""Layer 2: the refusal path emits, and still refuses (directive §5, §6.5).

The interesting case for an audit trail is not the statement that ran — it is the
one that *did not*. A caller reaching for privileged raw SQL without a privilege
must be recorded, because a refused escalation attempt is exactly the signal an
investigation needs. The same test asserts the refusal itself is unchanged: the
emission is additive, and a session wired with no sink behaves exactly as before.
"""

from __future__ import annotations

import json
import uuid

import pytest
import sqlalchemy as sa

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import AuthorizationError
from jdlib.persistence.rawsql import RawSqlMode
from jdlib.persistence.session import TenantSession
from jdlib.security.audit import (
    AuditRawSqlAuditor,
    SecurityAuditEvent,
    SecurityEventType,
)

pytestmark = pytest.mark.integration

TENANT_A = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
STATEMENT = sa.text("SELECT count(*) FROM invoices WHERE tenant_id = :tenant_id")


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    async def emit(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_A,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req-refused",
        correlation_id="corr-refused",
    )


async def _session(session_factory, *, auditor=None) -> TenantSession:
    raw = session_factory()
    await raw.execute(sa.text('SET search_path TO "jt_test"'))
    return TenantSession(raw, _context(), auditor=auditor)


async def test_a_refused_privileged_statement_is_recorded_and_still_refused(
    session_factory,
) -> None:
    sink = _RecordingSink()
    async with await _session(session_factory, auditor=AuditRawSqlAuditor(sink)) as session:
        with pytest.raises(AuthorizationError, match="privileged raw SQL"):
            await session.raw_sql(STATEMENT, {"tenant_id": TENANT_A}, mode=RawSqlMode.PRIVILEGED)

    (event,) = sink.events
    assert event.event_type is SecurityEventType.RAW_SQL_REJECTED
    assert event.tenant_id == TENANT_A
    assert event.metadata["reason"] == "privileged raw SQL requires a privileged context"
    assert event.request_id == "req-refused"
    stored = json.dumps(event.as_dict(), default=str)
    assert "invoices" not in stored, "the statement text is not evidence"
    assert event.metadata["statement"] == "select"


async def test_a_session_without_a_sink_behaves_exactly_as_before(session_factory) -> None:
    # The emission is additive: the default wiring records nothing and raises the
    # same error, so an existing deployment sees no change.
    async with await _session(session_factory) as session:
        with pytest.raises(AuthorizationError, match="privileged raw SQL"):
            await session.raw_sql(STATEMENT, {"tenant_id": TENANT_A}, mode=RawSqlMode.PRIVILEGED)


async def test_tenant_bound_raw_sql_is_not_recorded_as_privileged(session_factory) -> None:
    # Ordinary tenant-bound raw SQL is not a privileged act and must not be
    # promoted into the privileged ledger.
    sink = _RecordingSink()
    async with await _session(session_factory, auditor=AuditRawSqlAuditor(sink)) as session:
        await session.raw_sql(STATEMENT, {"tenant_id": TENANT_A})
    assert sink.events == []
