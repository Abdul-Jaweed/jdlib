import uuid

import pytest
import sqlalchemy as sa

from jdlib.context import Principal, PrincipalKind, TenantContext, context_scope
from jdlib.control.audit import CompositeAuditSink, DatabaseAuditSink
from jdlib.control.enums import PlacementStrategy
from jdlib.control.models import PlatformAuditEvent
from jdlib.control.registry import TenantRegistry
from jdlib.models.audit import AuditEvent
from jdlib.models.audit_recorder import TenantAuditRecorder


class _CapturingSink:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def record(self, *, action, tenant_id, actor_id, metadata=None, session=None) -> None:
        self.calls.append(
            {
                "action": action,
                "tenant_id": tenant_id,
                "actor_id": actor_id,
                "metadata": dict(metadata or {}),
                "session": session,
            }
        )


class _FailingSink:
    async def record(self, *, action, tenant_id, actor_id, metadata=None, session=None) -> None:
        raise RuntimeError("sink unavailable")


class _SessionCapturingSink(DatabaseAuditSink):
    def __init__(self, session_factory) -> None:
        super().__init__(session_factory)
        self.sessions: list[object | None] = []

    async def record(self, *, action, tenant_id, actor_id, metadata=None, session=None) -> None:
        self.sessions.append(session)
        await super().record(
            action=action,
            tenant_id=tenant_id,
            actor_id=actor_id,
            metadata=metadata,
            session=session,
        )


async def test_database_sink_writes_event_in_own_transaction(control_session_factory):
    sink = DatabaseAuditSink(control_session_factory)
    tenant_id = uuid.uuid4()
    await sink.record(
        action="tenant.created", tenant_id=tenant_id, actor_id=None, metadata={"x": 1}
    )
    async with control_session_factory() as session:
        row = (
            await session.execute(
                sa.select(PlatformAuditEvent).where(PlatformAuditEvent.tenant_id == tenant_id)
            )
        ).scalar_one()
    assert row.action == "tenant.created"
    assert row.metadata_json == {"x": 1}


async def test_database_sink_uses_caller_transaction(control_session_factory):
    sink = DatabaseAuditSink(control_session_factory)
    async with control_session_factory() as session:
        from jdlib.control.session import ControlPlaneSession

        await sink.record(
            action="tenant.suspended",
            tenant_id=None,
            actor_id=None,
            session=ControlPlaneSession(session),
        )
        await session.rollback()
    async with control_session_factory() as session:
        count = (
            await session.execute(
                sa.select(sa.func.count()).select_from(PlatformAuditEvent).where(
                    PlatformAuditEvent.action == "tenant.suspended"
                )
            )
        ).scalar_one()
    assert count == 0


async def test_composite_sink_fans_out_and_forwards_session():
    first = _CapturingSink()
    second = _CapturingSink()
    composite = CompositeAuditSink(first, second)
    marker = object()
    await composite.record(
        action="tenant.created",
        tenant_id=None,
        actor_id=None,
        metadata={"slug": "acme"},
        session=marker,
    )
    assert [call["action"] for call in first.calls] == ["tenant.created"]
    assert [call["action"] for call in second.calls] == ["tenant.created"]
    assert first.calls[0]["metadata"] == {"slug": "acme"}
    assert first.calls[0]["session"] is marker
    assert second.calls[0]["session"] is marker


async def test_composite_sink_propagates_failures():
    composite = CompositeAuditSink(_CapturingSink(), _FailingSink())
    with pytest.raises(RuntimeError):
        await composite.record(action="tenant.created", tenant_id=None, actor_id=None)


async def test_registry_records_audit_through_its_control_session(control_session_factory):
    sink = _SessionCapturingSink(control_session_factory)
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies={},
        runner=None,
        audit=sink,
    )
    slug = f"sink-{uuid.uuid4().hex[:8]}"
    tenant = await registry.create(
        slug=slug,
        name="Sink",
        strategy=PlacementStrategy.SHARED,
        target_handle="default",
    )
    assert len(sink.sessions) == 1
    assert sink.sessions[0] is not None
    async with control_session_factory() as session:
        event = (
            await session.execute(
                sa.select(PlatformAuditEvent).where(
                    PlatformAuditEvent.tenant_id == tenant.id,
                    PlatformAuditEvent.action == "tenant.created",
                )
            )
        ).scalar_one()
    assert event.metadata_json == {"slug": slug}


async def test_tenant_audit_recorder_commits_and_rolls_back(session_factory):
    tenant_id = uuid.uuid4()
    context = TenantContext(
        tenant_id=tenant_id,
        tenant_slug="audit",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
    )
    committed_action = f"invoice.updated.{uuid.uuid4().hex[:8]}"
    rolled_back_action = f"invoice.deleted.{uuid.uuid4().hex[:8]}"

    async with session_factory() as session:
        await session.execute(sa.text('SET search_path TO "jt_test"'))
        with context_scope(context):
            TenantAuditRecorder(session).record(
                action=committed_action, metadata={"status": "paid"}
            )
        await session.commit()

    async with session_factory() as session:
        await session.execute(sa.text('SET search_path TO "jt_test"'))
        row = (
            await session.execute(
                sa.select(AuditEvent).where(AuditEvent.action == committed_action)
            )
        ).scalar_one()
        assert row.tenant_id == tenant_id
        assert row.metadata_json == {"status": "paid"}
        with context_scope(context):
            TenantAuditRecorder(session).record(action=rolled_back_action)
        await session.rollback()

    async with session_factory() as session:
        await session.execute(sa.text('SET search_path TO "jt_test"'))
        count = (
            await session.execute(
                sa.select(sa.func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == rolled_back_action)
            )
        ).scalar_one()
    assert count == 0
