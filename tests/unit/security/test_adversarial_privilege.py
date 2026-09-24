"""Phase 8 (privilege expiry): authorization state must not outlive its lifetime.

The claim under attack: a privilege minted for a bounded window (`for_operator`
mints one with a TTL) stops authorizing anything the moment that window closes.
The audit trail's own vocabulary expects an answer — `PRIVILEGE_EXPIRED` exists —
and the directive's review list names session-boundary and privilege-expiry risk
explicitly.

These tests attack through the enforcement paths an application actually calls
(`TenantSession.raw_sql`, `delete_where`, `update_where`, `privileged_bypass`),
not through an internal helper, so a refusal here is a refusal an application
sees. Every refusal is also asserted to *not* reach the database: a privilege
that still executes is the worst available outcome.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
import sqlalchemy as sa

from jdlib.context import (
    Principal,
    PrincipalKind,
    PrivilegeContext,
    PrivilegeKind,
    TenantContext,
)
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import AuthorizationError
from jdlib.persistence.models import privileged_bypass
from jdlib.persistence.rawsql import RawSqlMode
from jdlib.persistence.session import TenantSession
from tests.support.invoice import Invoice

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


class Clock:
    """A clock the test moves, so expiry is exercised mid-session."""

    def __init__(self, now: datetime = NOW) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now

    def advance(self, **kwargs: float) -> None:
        self._now = self._now + timedelta(**kwargs)


def _operator() -> Principal:
    return Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4())


def _privilege(
    *,
    capability: str = "platform.raw_sql",
    kind: PrivilegeKind = PrivilegeKind.OPERATOR,
    issued_at: datetime = NOW,
    expires_at: datetime | None = None,
) -> PrivilegeContext:
    return PrivilegeContext(
        kind=kind,
        capability=capability,
        justification="INC-1234",
        actor=_operator(),
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _context(privilege: PrivilegeContext | None) -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req-priv",
        correlation_id="corr-priv",
        privilege=privilege,
    )


class _Result:
    rowcount = 0


class _StubAsyncSession:
    """Enough of an AsyncSession for the enforcement paths to run."""

    def __init__(self) -> None:
        self.sync_session = sa.orm.Session()
        self.bind = sa.create_engine("postgresql+psycopg://")
        self.executed: list[object] = []
        self.result: Any = _Result()

    async def execute(self, statement: sa.Executable, params: object = None) -> Any:
        self.executed.append(statement)
        return self.result


class _DenialAuditor:
    """Records refusals the way the audit adapter does (phase 6 seam)."""

    def __init__(self) -> None:
        self.denials: list[dict[str, object]] = []

    async def record_raw_sql(
        self, *, mode: RawSqlMode, capability: str | None, tenant_id: uuid.UUID, sql: str
    ) -> None:
        return None

    async def record_raw_sql_denied(
        self,
        *,
        mode: RawSqlMode,
        capability: str | None,
        tenant_id: uuid.UUID,
        sql: object,
        reason: str,
        principal_id: uuid.UUID | None = None,
        principal_kind: str | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        self.denials.append({"capability": capability, "reason": reason})


def _session(
    privilege: PrivilegeContext | None,
    *,
    clock: Clock | None = None,
    auditor: _DenialAuditor | None = None,
) -> tuple[TenantSession, _StubAsyncSession]:
    stub = _StubAsyncSession()
    session = TenantSession(
        cast(Any, stub),
        _context(privilege),
        auditor=auditor,
        clock=clock,
    )
    return session, stub


# --- privileged raw SQL --------------------------------------------------------


async def test_an_expired_privilege_cannot_run_privileged_raw_sql() -> None:
    clock = Clock()
    privilege = _privilege(
        expires_at=NOW - timedelta(seconds=1), issued_at=NOW - timedelta(hours=1)
    )
    auditor = _DenialAuditor()
    session, stub = _session(privilege, clock=clock, auditor=auditor)

    with pytest.raises(AuthorizationError):
        await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)

    assert stub.executed == [], "a refused statement must not reach the database"
    assert auditor.denials, "the refusal must be recorded before it is raised"
    assert "expire" in str(auditor.denials[0]["reason"]).lower()


async def test_a_live_privilege_still_authorizes() -> None:
    clock = Clock()
    session, stub = _session(_privilege(expires_at=NOW + timedelta(minutes=5)), clock=clock)

    await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)

    assert len(stub.executed) == 1


async def test_a_privilege_expires_between_two_uses() -> None:
    clock = Clock()
    session, stub = _session(_privilege(expires_at=NOW + timedelta(minutes=5)), clock=clock)

    await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    clock.advance(minutes=5)

    with pytest.raises(AuthorizationError):
        await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    assert len(stub.executed) == 1, "only the pre-expiry statement may execute"


async def test_the_expiry_boundary_itself_is_closed() -> None:
    """At exactly `expires_at` the privilege is over, not still valid."""
    clock = Clock()
    session, stub = _session(_privilege(expires_at=NOW), clock=clock)

    with pytest.raises(AuthorizationError):
        await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    assert stub.executed == []


async def test_a_privilege_used_before_it_was_issued_is_refused() -> None:
    """A clock that moves backwards must not resurrect authorization."""
    clock = Clock(NOW - timedelta(hours=1))
    session, stub = _session(
        _privilege(issued_at=NOW, expires_at=NOW + timedelta(minutes=5)), clock=clock
    )

    with pytest.raises(AuthorizationError):
        await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    assert stub.executed == []


async def test_an_unbounded_privilege_is_still_unbounded() -> None:
    """`expires_at is None` means no expiry — a system context keeps working."""
    session, stub = _session(_privilege(expires_at=None), clock=Clock())
    await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    assert len(stub.executed) == 1


# --- privileged DML ------------------------------------------------------------


async def test_an_expired_privilege_cannot_hard_delete() -> None:
    session, stub = _session(_privilege(capability=None, expires_at=NOW - timedelta(minutes=1)))

    with pytest.raises(AuthorizationError):
        await session.delete_where(Invoice, Invoice.status == "void")
    assert stub.executed == []


async def test_an_expired_privilege_cannot_rewrite_a_tenant_id() -> None:
    session, stub = _session(_privilege(capability=None, expires_at=NOW - timedelta(minutes=1)))

    with pytest.raises(AuthorizationError):
        await session.update_where(Invoice, {"tenant_id": uuid.uuid4()}, Invoice.status == "void")
    assert stub.executed == []


async def test_a_live_privilege_may_still_hard_delete() -> None:
    session, stub = _session(
        _privilege(capability=None, expires_at=NOW + timedelta(minutes=5)), clock=Clock()
    )

    rows = await session.delete_where(Invoice, Invoice.status == "void")

    assert rows == 0
    assert len(stub.executed) == 1


# --- the unit-of-work write fence ---------------------------------------------


def test_an_expired_system_privilege_cannot_bypass_the_write_fence() -> None:
    """Relocation bypass is a privileged operation; an expired one is not."""
    live = _privilege(
        capability="relocation.manage",
        kind=PrivilegeKind.SYSTEM,
        expires_at=NOW + timedelta(minutes=1),
    )
    expired = _privilege(
        capability="relocation.manage",
        kind=PrivilegeKind.SYSTEM,
        expires_at=NOW - timedelta(minutes=1),
    )

    assert privileged_bypass(_context(live), now=NOW) is True
    assert privileged_bypass(_context(expired), now=NOW) is False
