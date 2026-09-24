"""Audit producers for the successor capabilities (Phase 12).

The directive's requirement is that every new capability's security events reach a sink, so the
assertions here are about wiring rather than wording: for each event type, a producer exists and
emits it, with the right outcome, on the right path.

Where an event type already existed it is reused rather than shadowed - credential rotation is
`CREDENTIAL_ROTATED`, and a delegation is a privilege, so it is `PRIVILEGE_USED` on acceptance
and `AUTHZ_DENY` on refusal (ADR-3: one privilege vocabulary, not two). Five names are genuinely
new and are pinned by name in the vocabulary test.

The fail-closed property is tested as behavior, not as documentation: an emitter that raises
does not soften a refusal, and an emitter that is absent does not turn a success into a failure.
Audit is configuration; it is never a precondition for serving a request or for refusing one.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from jdlib.caching.keys import ScopedKeyFactory
from jdlib.caching.local import LocalCache
from jdlib.context import (
    Principal,
    PrincipalKind,
    PrivilegeContext,
    PrivilegeKind,
    TenantContext,
    validate_delegation,
)
from jdlib.control.enums import PlacementStrategy
from jdlib.credentials.rotation import VersionedSecretProvider
from jdlib.data.postgres import PostgresConnector
from jdlib.data.registry import ConnectorRegistry
from jdlib.errors import DelegationRefusedError
from jdlib.persistence.secrets import MemorySecretProvider
from jdlib.query.compiler import QueryCompiler
from jdlib.query.errors import CrossTenantQueryError, QueryParseError
from jdlib.query.safety import IdentifierPolicy
from jdlib.query.specification import QuerySpecification
from jdlib.resources.errors import ResourceHydrationError
from jdlib.resources.handle import ResourceHandle
from jdlib.resources.resolver import ResourceResolver
from jdlib.security.audit.emitter import AsyncSinkEmitter, emit_safely
from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.context import AuthMethod, SecurityContext, security_context_scope
from tests.support.context_fakes import CallableClock

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
HANDLE = "db/main"
TARGET = "postgresql+asyncpg://user@host:5432/db"  # noqa: S105 - a target, not a secret
SECRET = "s3cr3t-material-that-must-not-be-recorded"
CAPABILITY = "read:events"
NOW = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)


class _Recorder:
    """A sink. The point of the phase is that these calls happen."""

    def __init__(self, *, fail: bool = False) -> None:
        self.events: list[SecurityAuditEvent] = []
        self._fail = fail

    def __call__(self, event: SecurityAuditEvent) -> None:
        if self._fail:
            raise RuntimeError("audit sink unavailable")
        self.events.append(event)

    @property
    def types(self) -> list[SecurityEventType]:
        return [event.event_type for event in self.events]


def _context() -> SecurityContext:
    tenant = TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req-1",
        correlation_id="corr-1",
        trace_id=None,
    )
    return SecurityContext.from_tenant_context(tenant=tenant, auth_method=AuthMethod.SERVICE)


def _policy() -> IdentifierPolicy:
    return IdentifierPolicy(
        tables={"events": ("id", "kind")},
        tenant_scoped=("events",),
        tenant_plane=("projects",),
    )


def _resolver(recorder: _Recorder) -> ResourceResolver:
    return ResourceResolver(
        secrets=VersionedSecretProvider(MemorySecretProvider({HANDLE: TARGET})),
        cache=LocalCache(
            keys=ScopedKeyFactory(), clock=CallableClock(datetime(2026, 9, 24, tzinfo=UTC))
        ),
        emitter=recorder,
    )


def _delegation(**overrides) -> PrivilegeContext:
    values: dict[str, object] = {
        "kind": PrivilegeKind.DELEGATION,
        "delegation_id": "deleg-0001",
        "capability": CAPABILITY,
        "justification": "nightly reconciliation",
        "actor": Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), tenant_id=TENANT_ID),
        "issued_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(overrides)
    return PrivilegeContext(**values)  # type: ignore[arg-type]


# --- one producer per event type -------------------------------------------------------------


def test_registering_a_connector_emits_connector_registered() -> None:
    recorder = _Recorder()
    registry = ConnectorRegistry(emitter=recorder)

    name = registry.register(PostgresConnector)

    assert recorder.types == [SecurityEventType.CONNECTOR_REGISTERED]
    assert recorder.events[0].outcome is AuditOutcome.SUCCESS
    assert recorder.events[0].resource_id == name


def test_acquiring_a_connector_emits_connector_acquired() -> None:
    recorder = _Recorder()
    registry = ConnectorRegistry(emitter=recorder)
    name = registry.register(PostgresConnector)
    recorder.events.clear()

    registry.build(name)

    assert recorder.types == [SecurityEventType.CONNECTOR_ACQUIRED]
    assert recorder.events[0].resource_id == name


def test_a_rejected_query_emits_query_rejected() -> None:
    recorder = _Recorder()
    compiler = QueryCompiler(policy=_policy(), emitter=recorder)
    spec = QuerySpecification(table="not_allowed", columns=["id"], limit=10)

    with pytest.raises(QueryParseError):
        compiler.compile(spec, context=_context())

    assert recorder.types == [SecurityEventType.QUERY_REJECTED]
    assert recorder.events[0].outcome is AuditOutcome.DENIED


def test_a_cross_tenant_query_emits_cross_tenant_access_rejected() -> None:
    recorder = _Recorder()
    compiler = QueryCompiler(policy=_policy(), emitter=recorder)
    spec = QuerySpecification(table="events", columns=["id"], limit=10)

    with pytest.raises(CrossTenantQueryError):
        compiler.compile(spec, context=None)

    assert recorder.types == [SecurityEventType.CROSS_TENANT_ACCESS_REJECTED]


async def test_hydration_emits_resource_hydrated() -> None:
    recorder = _Recorder()

    with security_context_scope(_context()):
        await _resolver(recorder).hydrate(ResourceHandle(HANDLE))

    assert recorder.types == [SecurityEventType.RESOURCE_HYDRATED]
    assert recorder.events[0].outcome is AuditOutcome.SUCCESS


async def test_a_refused_hydration_emits_resource_hydration_refused() -> None:
    recorder = _Recorder()

    with pytest.raises(ResourceHydrationError):
        await _resolver(recorder).hydrate(ResourceHandle(HANDLE))  # no context bound

    assert recorder.types == [SecurityEventType.RESOURCE_HYDRATION_REFUSED]
    assert recorder.events[0].outcome is AuditOutcome.DENIED


def test_rotating_a_credential_emits_credential_rotated_without_the_value() -> None:
    """The type already existed; what was missing was a producer, not a name."""
    recorder = _Recorder()
    provider = VersionedSecretProvider(MemorySecretProvider({HANDLE: SECRET}), emitter=recorder)

    provider.rotate(HANDLE, new_value="a-new-secret-value", version="v2")

    assert recorder.types == [SecurityEventType.CREDENTIAL_ROTATED]
    recorded = repr(recorder.events[0])
    assert "a-new-secret-value" not in recorded
    assert SECRET not in recorded
    assert recorder.events[0].resource_id == HANDLE


def test_an_acceptable_delegation_emits_privilege_used() -> None:
    recorder = _Recorder()

    validate_delegation(
        _delegation(),
        capability=CAPABILITY,
        target_tenant_id=TENANT_ID,
        now=NOW,
        emitter=recorder,
    )

    assert recorder.types == [SecurityEventType.PRIVILEGE_USED]
    assert recorder.events[0].tenant_id == TENANT_ID


def test_a_refused_delegation_emits_authz_deny_before_it_refuses() -> None:
    recorder = _Recorder()
    expired = _delegation(expires_at=NOW - timedelta(minutes=1))

    with pytest.raises(DelegationRefusedError):
        validate_delegation(
            expired,
            capability=CAPABILITY,
            target_tenant_id=TENANT_ID,
            now=NOW,
            emitter=recorder,
        )

    assert recorder.types == [SecurityEventType.AUTHZ_DENY]
    assert recorder.events[0].outcome is AuditOutcome.DENIED


def test_a_delegation_for_another_tenant_is_recorded_as_denied() -> None:
    recorder = _Recorder()
    elsewhere = _delegation(
        actor=Principal(
            kind=PrincipalKind.USER,
            id=uuid.uuid4(),
            tenant_id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
        )
    )

    with pytest.raises(DelegationRefusedError):
        validate_delegation(
            elsewhere,
            capability=CAPABILITY,
            target_tenant_id=TENANT_ID,
            now=NOW,
            emitter=recorder,
        )

    assert recorder.types == [SecurityEventType.AUTHZ_DENY]


# --- audit is configuration, never a precondition ---------------------------------------------


def test_a_failing_sink_does_not_soften_a_refusal() -> None:
    """The refusal is the decision, the record is the evidence: neither replaces the other."""
    compiler = QueryCompiler(policy=_policy(), emitter=_Recorder(fail=True))
    spec = QuerySpecification(table="not_allowed", columns=["id"], limit=10)

    with pytest.raises(QueryParseError):
        compiler.compile(spec, context=_context())


async def test_a_failing_sink_does_not_break_a_successful_operation() -> None:
    resolver = _resolver(_Recorder(fail=True))

    with security_context_scope(_context()):
        config = await resolver.hydrate(ResourceHandle(HANDLE))

    assert config.target == TARGET


def test_an_absent_sink_is_not_an_error_and_records_nothing() -> None:
    """The default is no emitter: a library that required one could not be embedded."""
    registry = ConnectorRegistry()

    name = registry.register(PostgresConnector)
    registry.build(name)

    assert name == "postgres"


def test_no_recorded_event_carries_a_credential_or_a_target() -> None:
    recorder = _Recorder()
    registry = ConnectorRegistry(emitter=recorder)
    name = registry.register(PostgresConnector)
    registry.build(name)

    recorded = " ".join(repr(event) for event in recorder.events)

    assert SECRET not in recorded
    assert TARGET not in recorded
    assert "postgresql" not in recorded


# --- the async-sink bridge ---------------------------------------------------------------------


class _AsyncSink:
    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    async def emit(self, event: SecurityAuditEvent) -> None:
        await asyncio.sleep(0)
        self.events.append(event)


async def test_an_async_sink_receives_events_through_the_bridge() -> None:
    """The boundaries are synchronous and the library's sinks are coroutines."""
    sink = _AsyncSink()
    bridge = AsyncSinkEmitter(sink)
    event = SecurityAuditEvent(
        event_type=SecurityEventType.CONNECTOR_ACQUIRED,
        outcome=AuditOutcome.SUCCESS,
        action="connector.acquire",
        source=AuditSource.SYSTEM,
    )

    assert emit_safely(bridge, event) is True
    await bridge.drain()

    assert sink.events == [event]


def test_the_bridge_reports_failure_when_there_is_no_running_loop() -> None:
    """Rather than inventing a thread pool: an out-of-order event is not the record it claims."""
    sink = _AsyncSink()
    event = SecurityAuditEvent(
        event_type=SecurityEventType.CONNECTOR_ACQUIRED,
        outcome=AuditOutcome.SUCCESS,
        action="connector.acquire",
        source=AuditSource.SYSTEM,
    )

    assert emit_safely(AsyncSinkEmitter(sink), event) is False
    assert sink.events == []
