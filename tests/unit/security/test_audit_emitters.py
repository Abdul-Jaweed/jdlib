"""Phase 6: turning decisions into audit events (directive §4).

The PEP already exposes an observer seam (``on_decision``) that was built for
exactly this: every decision — allow, deny or *degraded* — reaches an audit sink
without the enforcement path knowing anything about storage.

Properties under test:

* each decision shape maps to the right event type and outcome,
* the event describes the same question the engine was asked (resource, tenant,
  actions) and never carries policy internals,
* a degraded engine is recorded as an error, never as an allow or a plain deny,
* a sink that fails surfaces the failure instead of silently dropping evidence.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from jdlib.errors import PermissionDenied
from jdlib.security.audit import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.audit.emitters import (
    NullSecurityEventSink,
    TransactionAuditSink,
    authorization_audit_observer,
)
from jdlib.security.authz.decision import AuthorizationDecision, AuthorizationQuery
from jdlib.security.authz.pep import AuthorizationPEP

TENANT_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    async def emit(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)


class _FailingSink:
    async def emit(self, event: SecurityAuditEvent) -> None:
        raise RuntimeError("audit storage unavailable")


class _StubPDP:
    def __init__(self, decision: AuthorizationDecision) -> None:
        self._decision = decision

    async def decide(self, query: AuthorizationQuery) -> AuthorizationDecision:
        return self._decision


def _query(*actions: str) -> AuthorizationQuery:
    return AuthorizationQuery(
        principal_id="user-1",
        tenant_id=TENANT_ID,
        resource_kind="document",
        resource_id="doc-42",
        actions=actions or ("read",),
        request_id="req-1",
    )


def _allowed() -> AuthorizationDecision:
    return AuthorizationDecision.allow(
        decided_at=datetime(2026, 6, 1, tzinfo=UTC), policy_id="resource.document.vdefault"
    )


def _denied() -> AuthorizationDecision:
    return AuthorizationDecision.deny(
        reason="no_allow",
        decided_at=datetime(2026, 6, 1, tzinfo=UTC),
        denied_actions=("read",),
    )


def _degraded() -> AuthorizationDecision:
    return AuthorizationDecision.unavailable(
        reason="engine_unavailable", decided_at=datetime(2026, 6, 1, tzinfo=UTC)
    )


async def test_an_allow_is_recorded_as_an_allow() -> None:
    sink = _RecordingSink()
    observer = authorization_audit_observer(sink, source=AuditSource.SERVICE)
    await observer(_query(), _allowed())
    event = sink.events[0]
    assert event.event_type is SecurityEventType.AUTHZ_ALLOW
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.tenant_id == TENANT_ID
    assert event.resource_type == "document"
    assert event.resource_id == "doc-42"
    assert event.action == "read"
    assert event.source is AuditSource.SERVICE


async def test_a_denial_is_recorded_with_its_reason() -> None:
    sink = _RecordingSink()
    observer = authorization_audit_observer(sink)
    await observer(_query(), _denied())
    event = sink.events[0]
    assert event.event_type is SecurityEventType.AUTHZ_DENY
    assert event.outcome is AuditOutcome.DENIED
    assert event.metadata["reason"] == "no_allow"
    assert event.metadata["denied_actions"] == ["read"]


async def test_a_degraded_engine_is_recorded_as_an_error() -> None:
    sink = _RecordingSink()
    observer = authorization_audit_observer(sink)
    await observer(_query(), _degraded())
    event = sink.events[0]
    assert event.event_type is SecurityEventType.AUTHZ_PDP_ERROR
    assert event.outcome is AuditOutcome.ERROR
    assert event.metadata["reason"] == "engine_unavailable"


async def test_multi_action_queries_keep_every_action() -> None:
    sink = _RecordingSink()
    observer = authorization_audit_observer(sink)
    await observer(_query("read", "write"), _allowed())
    assert sink.events[0].action == "read,write"


async def test_events_never_carry_policy_internals() -> None:
    sink = _RecordingSink()
    observer = authorization_audit_observer(sink)
    await observer(_query(), _allowed())
    rendered = str(sink.events[0].metadata)
    assert "resource.document" not in rendered  # fully-qualified policy name
    assert "vdefault" not in rendered
    assert set(sink.events[0].metadata) <= {
        "decision",
        "reason",
        "denied_actions",
        "principal_ref",
    }


async def test_a_non_uuid_principal_is_preserved_by_reference() -> None:
    # Federated subjects are not UUIDs; the audit trail must still name them.
    sink = _RecordingSink()
    observer = authorization_audit_observer(sink)
    await observer(_query(), _denied())
    event = sink.events[0]
    assert event.principal_id is None
    assert event.metadata["principal_ref"] == "user-1"


async def test_a_uuid_principal_is_stored_as_the_actor() -> None:
    principal_id = uuid.uuid4()
    query = AuthorizationQuery(
        principal_id=str(principal_id),
        tenant_id=TENANT_ID,
        resource_kind="document",
        resource_id="doc-42",
        actions=("read",),
    )
    sink = _RecordingSink()
    await authorization_audit_observer(sink)(query, _denied())
    assert sink.events[0].principal_id == principal_id
    assert "principal_ref" not in sink.events[0].metadata


async def test_a_failing_sink_surfaces_the_failure() -> None:
    observer = authorization_audit_observer(_FailingSink())
    with pytest.raises(RuntimeError, match="audit storage unavailable"):
        await observer(_query(), _denied())


async def test_the_observer_plugs_into_the_enforcement_point() -> None:
    # The seam built in Phase 3 is what carries this: enforcement neither knows
    # nor cares that a sink exists.
    sink = _RecordingSink()
    pep = AuthorizationPEP(pdp=_StubPDP(_denied()), on_decision=authorization_audit_observer(sink))
    with pytest.raises(PermissionDenied):
        await pep.require(_query())
    assert [event.event_type for event in sink.events] == [SecurityEventType.AUTHZ_DENY]


async def test_the_observer_does_not_change_the_decision() -> None:
    sink = _RecordingSink()
    pep = AuthorizationPEP(pdp=_StubPDP(_allowed()), on_decision=authorization_audit_observer(sink))
    decision = await pep.require(_query())
    assert decision.allowed is True
    assert [event.event_type for event in sink.events] == [SecurityEventType.AUTHZ_ALLOW]


async def test_null_sink_accepts_events_without_storing_them() -> None:
    sink = NullSecurityEventSink()
    await sink.emit(
        SecurityAuditEvent(
            event_type=SecurityEventType.AUTHZ_ALLOW,
            outcome=AuditOutcome.SUCCESS,
            action="read",
            source=AuditSource.SYSTEM,
        )
    )


async def test_transaction_sink_writes_through_the_recorder() -> None:
    class _Session:
        def __init__(self) -> None:
            self.added: list[object] = []

        def add(self, instance: object) -> None:
            self.added.append(instance)

    from jdlib.context import Principal, PrincipalKind, TenantContext, context_scope
    from jdlib.control.enums import PlacementStrategy

    session = _Session()
    sink = TransactionAuditSink(session)
    context = TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(id=uuid.uuid4(), kind=PrincipalKind.USER),
        request_id="req-1",
        correlation_id="corr-1",
    )
    event = SecurityAuditEvent(
        event_type=SecurityEventType.AUTHZ_DENY,
        outcome=AuditOutcome.DENIED,
        action="read",
        source=AuditSource.API,
    )
    with context_scope(context):
        await sink.emit(event)
    assert len(session.added) == 1
    row = session.added[0]
    assert getattr(row, "event_type", None) == "AUTHZ_DENY"
    assert getattr(row, "tenant_id", None) == TENANT_ID
