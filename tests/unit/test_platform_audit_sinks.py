from __future__ import annotations

import uuid

from jdlib.context import Principal, PrincipalKind, PrivilegeKind, TenantContext, context_scope
from jdlib.control.audit import (
    DatabaseAuditSink,
    PrivilegeAuditAdapter,
    RecordingPlatformAudit,
)
from jdlib.control.enums import PlacementStrategy


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=uuid.UUID(int=1),
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.UUID(int=2)),
        request_id="req-1",
        correlation_id="corr-1",
        trace_id="trace-1",
    )


class _FakeSession:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.committed = False

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.committed = True

    async def close(self) -> None:
        return None


async def test_database_sink_infers_actor_type_from_actor_id():
    session = _FakeSession()
    sink = DatabaseAuditSink(lambda: session)  # type: ignore[arg-type,return-value]
    await sink.record(action="tenant.created", tenant_id=None, actor_id=uuid.uuid4())
    assert session.added[0].actor_type == "user"  # type: ignore[attr-defined]
    assert session.committed is True


async def test_database_sink_honors_explicit_actor_type():
    session = _FakeSession()
    sink = DatabaseAuditSink(lambda: session)  # type: ignore[arg-type,return-value]
    await sink.record(
        action="privilege.operator",
        tenant_id=None,
        actor_id=uuid.uuid4(),
        actor_type="platform_operator",
    )
    assert session.added[0].actor_type == "platform_operator"  # type: ignore[attr-defined]


async def test_database_sink_populates_trace_ids_from_active_context():
    session = _FakeSession()
    sink = DatabaseAuditSink(lambda: session)  # type: ignore[arg-type,return-value]
    with context_scope(_context()):
        await sink.record(action="tenant.created", tenant_id=uuid.UUID(int=1), actor_id=None)
    event = session.added[0]
    assert event.request_id == "req-1"  # type: ignore[attr-defined]
    assert event.correlation_id == "corr-1"  # type: ignore[attr-defined]
    assert event.trace_id == "trace-1"  # type: ignore[attr-defined]


async def test_database_sink_leaves_trace_ids_null_without_context():
    session = _FakeSession()
    sink = DatabaseAuditSink(lambda: session)  # type: ignore[arg-type,return-value]
    await sink.record(action="tenant.created", tenant_id=None, actor_id=None)
    event = session.added[0]
    assert event.request_id is None  # type: ignore[attr-defined]
    assert event.correlation_id is None  # type: ignore[attr-defined]
    assert event.trace_id is None  # type: ignore[attr-defined]


async def test_privilege_audit_adapter_delegates_to_platform_sink():
    sink = RecordingPlatformAudit()
    adapter = PrivilegeAuditAdapter(sink)
    actor = Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4())
    tenant_id = uuid.uuid4()
    await adapter.record_privilege(
        kind=PrivilegeKind.OPERATOR,
        capability="platform.tenant.access",
        justification="support case 123",
        actor=actor,
        tenant_id=tenant_id,
    )
    assert sink.entries == [
        {
            "action": "privilege.operator",
            "tenant_id": tenant_id,
            "actor_id": actor.id,
            "metadata": {
                "capability": "platform.tenant.access",
                "justification": "support case 123",
            },
            "actor_type": "platform_operator",
        }
    ]
