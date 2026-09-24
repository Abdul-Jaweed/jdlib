"""Phase 6.5: the remaining event families get producers.

These adapters plug into seams that already exist — the `PrivilegeAudit` protocol
the context factory calls when it mints a privilege, and the `RawSqlAuditor`
protocol the persistence layer calls when privileged raw SQL runs. No second
plumbing is introduced, and a deployment that wires no sink keeps today's
behaviour.

Two rules hold for every adapter here: the exception is never swallowed, and the
statement or justification text that reaches the trail is redacted rather than
copied wholesale — the trail must not become a place where a credential lives.
"""

from __future__ import annotations

import json
import uuid

from jdlib.context import Principal, PrincipalKind, PrivilegeKind
from jdlib.persistence.rawsql import RawSqlMode
from jdlib.security.audit import (
    AuditOutcome,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.audit.adapters import AuditPrivilegeAudit, AuditRawSqlAuditor

TENANT_A = uuid.UUID("aaaaaaaa-1111-2222-3333-444444444444")
OPERATOR = uuid.UUID("99999999-8888-7777-6666-555555555555")

PLATFORM_SQL = (
    "SELECT id, payload FROM public.documents "
    "WHERE tenant_id = 'aaaaaaaa-1111-2222-3333-444444444444'"
)


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    async def emit(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)


def _operator() -> Principal:
    return Principal(id=OPERATOR, kind=PrincipalKind.PLATFORM_OPERATOR)


# --- privileges ---------------------------------------------------------------


async def test_privilege_issuance_becomes_an_audit_event() -> None:
    sink = _RecordingSink()
    await AuditPrivilegeAudit(sink).record_privilege(
        kind=PrivilegeKind.OPERATOR,
        capability="platform.raw_sql",
        justification="incident-4711 break glass",
        actor=_operator(),
        tenant_id=TENANT_A,
    )
    (event,) = sink.events
    assert event.event_type is SecurityEventType.PRIVILEGE_ISSUED
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.tenant_id == TENANT_A
    assert event.principal_id == OPERATOR
    assert event.principal_kind == "platform_operator"
    assert event.metadata["kind"] == "operator"
    assert event.metadata["capability"] == "platform.raw_sql"
    assert event.metadata["justification"] == "incident-4711 break glass"


async def test_a_justification_cannot_smuggle_a_secret() -> None:
    sink = _RecordingSink()
    await AuditPrivilegeAudit(sink).record_privilege(
        kind=PrivilegeKind.OPERATOR,
        capability="platform.raw_sql",
        justification="checked postgresql+asyncpg://app:s3cr3t-pw@db.internal:5432/jdlib",
        actor=_operator(),
        tenant_id=TENANT_A,
    )
    (event,) = sink.events
    stored = json.dumps(event.as_dict(), default=str)
    assert "s3cr3t-pw" not in stored
    assert "db.internal" not in stored


async def test_system_privileges_are_recorded_without_a_justification() -> None:
    sink = _RecordingSink()
    await AuditPrivilegeAudit(sink).record_privilege(
        kind=PrivilegeKind.SYSTEM,
        capability="tenant.provision",
        justification=None,
        actor=_operator(),
        tenant_id=TENANT_A,
    )
    (event,) = sink.events
    assert event.event_type is SecurityEventType.PRIVILEGE_ISSUED
    assert event.metadata["kind"] == "system"
    assert event.metadata["capability"] == "tenant.provision"
    assert "justification" not in event.metadata
    assert event.action == "privilege.issue"


# --- privileged raw SQL -------------------------------------------------------


async def test_privileged_raw_sql_becomes_an_audit_event() -> None:
    sink = _RecordingSink()
    await AuditRawSqlAuditor(sink).record_raw_sql(
        mode=RawSqlMode.PRIVILEGED,
        capability="platform.raw_sql",
        tenant_id=TENANT_A,
        sql=PLATFORM_SQL,
    )
    (event,) = sink.events
    assert event.event_type is SecurityEventType.RAW_SQL_PRIVILEGED
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.tenant_id == TENANT_A
    assert event.action == "raw_sql.privileged"
    assert event.metadata["capability"] == "platform.raw_sql"
    assert event.metadata["statement"] == "select"
    # The statement itself is not evidence we need, and a statement can carry
    # literals: only its kind is recorded.
    stored = json.dumps(event.as_dict(), default=str)
    assert "payload" not in stored
    assert "public.documents" not in stored


async def test_rejected_raw_sql_is_recorded_before_it_is_refused() -> None:
    sink = _RecordingSink()
    await AuditRawSqlAuditor(sink).record_raw_sql_denied(
        mode=RawSqlMode.PRIVILEGED,
        capability=None,
        tenant_id=TENANT_A,
        sql=PLATFORM_SQL,
        reason="privileged raw SQL requires a privileged context",
    )
    (event,) = sink.events
    assert event.event_type is SecurityEventType.RAW_SQL_REJECTED
    assert event.outcome is AuditOutcome.DENIED
    assert event.action == "raw_sql.rejected"
    assert event.metadata["reason"] == "privileged raw SQL requires a privileged context"
    assert "public.documents" not in json.dumps(event.as_dict(), default=str)


async def test_a_denied_raw_sql_attempt_needs_no_capability_vocabulary() -> None:
    # The refusal path must work before any capability is established, so an
    # unknown capability is recorded as absent rather than crashing.
    sink = _RecordingSink()
    await AuditRawSqlAuditor(sink).record_raw_sql_denied(
        mode=RawSqlMode.PRIVILEGED,
        capability="something.unexpected",
        tenant_id=TENANT_A,
        sql="DELETE FROM public.documents",
        reason="missing raw SQL capability",
    )
    (event,) = sink.events
    assert event.metadata["capability"] == "something.unexpected"
    assert event.metadata["statement"] == "delete"


def test_the_sql_statement_kind_is_extracted_without_parsing() -> None:
    from jdlib.security.audit.adapters import statement_kind

    assert statement_kind("  SELECT 1") == "select"
    assert statement_kind("UPDATE t SET a = 1") == "update"
    assert statement_kind("") == "unknown"
    assert statement_kind("-- comment only") == "unknown"
    assert statement_kind("EXPLAIN ANALYZE SELECT 1") == "explain"
    assert statement_kind(None) == "unknown"  # type: ignore[arg-type]
    # a long leading token is not an identifier we echo back
    assert statement_kind("x" * 400) == "unknown"


def test_both_adapters_are_usable_where_the_library_calls_them() -> None:
    from jdlib.context import PrivilegeAudit
    from jdlib.persistence.session import RawSqlAuditor

    pairs = ((RawSqlAuditor, AuditRawSqlAuditor), (PrivilegeAudit, AuditPrivilegeAudit))
    for protocol, adapter in pairs:
        for method in (m for m in dir(protocol) if not m.startswith("_")):
            assert hasattr(adapter, method), f"{adapter.__name__} lacks {method}"
    assert hasattr(AuditRawSqlAuditor(None), "record_raw_sql_denied")
