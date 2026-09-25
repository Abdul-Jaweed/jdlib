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
        self.statements: list[tuple[str, dict[str, object]]] = []

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def execute(self, statement: object, parameters: dict[str, object] | None = None) -> None:
        self.statements.append((str(statement), dict(parameters or {})))

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.committed = True

    async def close(self) -> None:
        return None


async def test_database_sink_names_the_request_on_the_session_it_writes_from():
    """The statement that writes a request's evidence names the request.

    `observability-validation.md` §6.3 measured that nothing about the statement identified
    the request: the pool carried the default client name, so PostgreSQL's own log line and
    `pg_stat_activity` said nothing about who asked. The sink sets `application_name` for its
    own transaction - `set_config(..., true)`, which is the parameterised, transaction-scoped
    form of `SET LOCAL` - so the INSERT that stores the row carries the correlation id.
    """
    session = _FakeSession()
    sink = DatabaseAuditSink(lambda: session)  # type: ignore[arg-type,return-value]

    await sink.record(
        action="security.AUTHZ_ALLOW",
        tenant_id=None,
        actor_id=uuid.uuid4(),
        correlation_id="corr-1",
    )

    assert len(session.statements) == 1
    statement, parameters = session.statements[0]
    assert "set_config('application_name'" in statement
    assert parameters == {"name": "corr-1"}


async def test_database_sink_sets_no_session_name_without_a_request_id():
    """A write with no request behind it (startup, a script) leaves the session name alone:
    an invented id in PostgreSQL's log would be worse than none."""
    session = _FakeSession()
    sink = DatabaseAuditSink(lambda: session)  # type: ignore[arg-type,return-value]

    await sink.record(action="tenant.created", tenant_id=None, actor_id=uuid.uuid4())

    assert session.statements == []


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
            # Recorded entries now carry the identifiers too: the adapter's own
            # privilege path passes none, so they fall back to the ambient context,
            # which is absent here - and the recorder reports that honestly rather
            # than inventing one.
            "request_id": None,
            "correlation_id": None,
            "trace_id": None,
            "actor_type": "platform_operator",
        }
    ]


async def test_database_sink_prefers_the_identifiers_the_caller_supplies():
    """Identifiers travel with the event, not with the task that writes it.

    The reference application's control-plane trail is drained by a worker task
    created at startup, so no request context is bound when the row is staged: with
    only the ambient lookup every row carried `NULL` identifiers, and an operator
    could not join a decision to the request that caused it. A caller that already
    holds the identifiers -- an adapter forwarding an event that carries them --
    must be able to pass them.
    """

    session = _FakeSession()
    sink = DatabaseAuditSink(lambda: session)
    await sink.record(
        action="security.authz_allow",
        tenant_id=uuid.UUID(int=1),
        actor_id=uuid.UUID(int=2),
        request_id="req-9",
        correlation_id="corr-9",
        trace_id="trace-9",
    )

    row = session.added[0]
    assert row.request_id == "req-9"
    assert row.correlation_id == "corr-9"
    assert row.trace_id == "trace-9"


async def test_database_sink_still_falls_back_to_the_ambient_context():
    """The behaviour every existing caller relies on is unchanged."""

    session = _FakeSession()
    sink = DatabaseAuditSink(lambda: session)
    with context_scope(_context()):
        await sink.record(action="security.authz_allow", tenant_id=uuid.UUID(int=1), actor_id=None)

    row = session.added[0]
    assert (row.request_id, row.correlation_id, row.trace_id) == ("req-1", "corr-1", "trace-1")
