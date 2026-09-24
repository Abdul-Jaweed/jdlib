"""Phase 8 (audit integrity): a trail that can be mis-attributed is not evidence.

The claim under attack: every row in the security audit trail names the actor who
caused it and the time it happened. The directive's review list asks for exactly
these two attacks — *forged actor* and *timestamp manipulation* — and for the
refusal to be visible rather than silent.

The attacker here is application code that feeds request-derived data into an
audit call (a common shape: an admin endpoint recording "action performed on
behalf of <id from the request>"). If such a value can override the ambient
principal, an investigation is pointed at whoever the caller named.

Refusal is fail-closed: the event is not written and the operation fails, because
an operation whose evidence is a lie is worse than an operation with no evidence.
The tenant-mismatch refusal that already existed is pinned alongside these so the
two guarantees cannot drift apart.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from jdlib.context import Principal, PrincipalKind, TenantContext, context_scope
from jdlib.control.enums import PlacementStrategy
from jdlib.models.audit_recorder import TenantAuditRecorder
from jdlib.security.audit import AuditOutcome, AuditSource, SecurityAuditEvent, SecurityEventType

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self, now: datetime = NOW) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


class _Session:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, obj: object) -> None:
        self.added.append(obj)


def _context(principal: Principal) -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req-audit",
        correlation_id="corr-audit",
    )


def _caller() -> Principal:
    return Principal(kind=PrincipalKind.USER, id=uuid.uuid4())


def _event(**overrides: object) -> SecurityAuditEvent:
    fields: dict[str, object] = {
        "event_type": SecurityEventType.AUTHZ_DENY,
        "outcome": AuditOutcome.DENIED,
        "action": "invoice.read",
        "source": AuditSource.API,
        "tenant_id": TENANT_ID,
        "occurred_at": NOW,
    }
    fields.update(overrides)
    return SecurityAuditEvent(**fields)  # type: ignore[arg-type]


def _recorder(session: _Session) -> TenantAuditRecorder:
    return TenantAuditRecorder(session, clock=Clock())


# --- forged actor --------------------------------------------------------------


def test_an_event_naming_another_actor_is_refused() -> None:
    session = _Session()
    caller = _caller()
    with context_scope(_context(caller)), pytest.raises(ValueError, match="actor"):
        _recorder(session).record_security(
            _event(principal_id=uuid.uuid4(), principal_kind=PrincipalKind.USER.value)
        )
    assert session.added == [], "a mis-attributed row must not be written"


def test_an_event_claiming_another_actor_kind_is_refused() -> None:
    session = _Session()
    caller = _caller()
    with context_scope(_context(caller)), pytest.raises(ValueError, match="actor"):
        _recorder(session).record_security(
            _event(principal_id=caller.id, principal_kind=PrincipalKind.PLATFORM_OPERATOR.value)
        )
    assert session.added == []


def test_an_event_without_an_actor_is_attributed_to_the_caller() -> None:
    session = _Session()
    caller = _caller()
    with context_scope(_context(caller)):
        row = _recorder(session).record_security(_event())

    assert row.actor_id == caller.id
    assert row.actor_type == PrincipalKind.USER.value
    assert session.added == [row]


def test_a_tenant_mismatch_is_still_refused() -> None:
    """The guarantee phase 6 established, pinned next to the new one."""
    session = _Session()
    with context_scope(_context(_caller())), pytest.raises(ValueError, match="tenant"):
        _recorder(session).record_security(_event(tenant_id=uuid.uuid4()))
    assert session.added == []


# --- timestamp manipulation ----------------------------------------------------


def test_a_backdated_event_is_refused() -> None:
    session = _Session()
    with context_scope(_context(_caller())), pytest.raises(ValueError, match="timestamp"):
        _recorder(session).record_security(_event(occurred_at=NOW - timedelta(hours=6)))
    assert session.added == [], "backdating must not reach the trail"


def test_a_future_dated_event_is_refused() -> None:
    session = _Session()
    with context_scope(_context(_caller())), pytest.raises(ValueError, match="timestamp"):
        _recorder(session).record_security(_event(occurred_at=NOW + timedelta(hours=6)))
    assert session.added == []


def test_a_timestamp_within_clock_tolerance_is_accepted() -> None:
    session = _Session()
    with context_scope(_context(_caller())):
        row = _recorder(session).record_security(_event(occurred_at=NOW - timedelta(seconds=5)))

    assert row.occurred_at == NOW - timedelta(seconds=5)
    assert session.added == [row]


def test_the_boundary_of_the_tolerance_is_closed() -> None:
    """Exactly at the tolerance is still the clock talking; past it is not."""
    session = _Session()
    with context_scope(_context(_caller())), pytest.raises(ValueError, match="timestamp"):
        _recorder(session).record_security(
            _event(occurred_at=NOW - timedelta(minutes=5) - timedelta(seconds=1))
        )
    assert session.added == []


def test_the_model_still_models_history_even_though_writes_refuse_it() -> None:
    """Refusal lives on the write path: reconstructing an old row is not a write.

    Export rebuilds envelopes from stored rows (which carry their original
    timestamps) without going through the recorder, so read paths keep working.
    """
    old = _event(occurred_at=datetime(2020, 1, 1, tzinfo=UTC))
    assert old.occurred_at == datetime(2020, 1, 1, tzinfo=UTC)


# --- an async session must not swallow the row ----------------------------------


class _AsyncSession:
    """A session whose ``add`` is awaitable, like JDLib's own ``TenantSession``.

    The recorder's synchronous path cannot await it, and a discarded coroutine
    means the row is never staged. A trail that loses events whenever the caller
    happens to be async is not a trail.
    """

    def __init__(self) -> None:
        self.added: list[object] = []

    async def add(self, obj: object) -> None:
        self.added.append(obj)


async def test_the_async_recorder_stages_the_row_on_an_awaitable_session() -> None:
    session = _AsyncSession()
    caller = _caller()

    with context_scope(_context(caller)):
        row = await TenantAuditRecorder(session, clock=Clock()).arecord_security(
            _event(principal_id=caller.id, principal_kind=caller.kind.value)
        )

    assert session.added == [row]
    assert row.actor_id == caller.id


def test_the_sync_recorder_refuses_an_awaitable_session() -> None:
    """A write that cannot happen here is refused, not lost silently."""

    session = _AsyncSession()
    caller = _caller()

    with (
        context_scope(_context(caller)),
        pytest.raises(TypeError, match="awaitable"),
    ):
        TenantAuditRecorder(session, clock=Clock()).record_security(
            _event(principal_id=caller.id, principal_kind=caller.kind.value)
        )

    assert session.added == []
