import uuid
from datetime import UTC, datetime

import pytest

from jdlib.context import (
    Principal,
    PrincipalKind,
    PrivilegeContext,
    PrivilegeKind,
    TenantContext,
)
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import TenantNotWritable
from jdlib.persistence.uow import UnitOfWork

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _context(privilege: PrivilegeContext | None = None) -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
        privilege=privilege,
    )


def _operator_privilege() -> PrivilegeContext:
    return PrivilegeContext(
        kind=PrivilegeKind.OPERATOR,
        capability="relocation.manage",
        justification="ticket",
        actor=Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4()),
        issued_at=datetime.now(UTC),
        expires_at=None,
    )


class _FakeSession:
    def __init__(self) -> None:
        self.committed = False
        self.rolled_back = False
        self.closed = False
        self.info: dict[str, object] = {}

        class _Sync:
            pass

        self.sync_session = _Sync()
        self.bind = type("Bind", (), {"dialect": None})()

    async def close(self) -> None:
        self.closed = True

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True


class _Factory:
    def __init__(self) -> None:
        self.sessions: list[_FakeSession] = []

    def __call__(self) -> _FakeSession:
        session = _FakeSession()
        self.sessions.append(session)
        return session


class _Fence:
    def __init__(self, blocked: bool = False) -> None:
        self.blocked = blocked
        self.calls = 0

    async def assert_writable(self, tenant_id: uuid.UUID) -> None:
        self.calls += 1
        if self.blocked:
            raise TenantNotWritable("relocation in progress")


async def test_commit_on_clean_exit(monkeypatch):
    factory = _Factory()
    monkeypatch.setattr(
        "jdlib.persistence.uow.TenantSession", lambda session, context, **kw: session
    )
    fence = _Fence()
    async with UnitOfWork(factory, _context(), fence=fence) as session:
        assert session is factory.sessions[0]
    assert factory.sessions[0].committed is True
    assert factory.sessions[0].closed is True
    assert fence.calls == 1


async def test_rollback_on_exception(monkeypatch):
    factory = _Factory()
    monkeypatch.setattr(
        "jdlib.persistence.uow.TenantSession", lambda session, context, **kw: session
    )
    with pytest.raises(RuntimeError):
        async with UnitOfWork(factory, _context(), fence=_Fence()) as _session:
            raise RuntimeError("boom")
    assert factory.sessions[0].rolled_back is True
    assert factory.sessions[0].committed is False
    assert factory.sessions[0].closed is True


async def test_fence_blocks_admission(monkeypatch):
    factory = _Factory()
    monkeypatch.setattr(
        "jdlib.persistence.uow.TenantSession", lambda session, context, **kw: session
    )
    with pytest.raises(TenantNotWritable):
        async with UnitOfWork(factory, _context(), fence=_Fence(blocked=True)):
            pass
    assert factory.sessions == []


async def test_operator_context_does_not_bypass_fence(monkeypatch):
    factory = _Factory()
    monkeypatch.setattr(
        "jdlib.persistence.uow.TenantSession", lambda session, context, **kw: session
    )
    fence = _Fence(blocked=True)
    with pytest.raises(TenantNotWritable):
        async with UnitOfWork(factory, _context(_operator_privilege()), fence=fence):
            pass
    assert fence.calls == 1
    assert factory.sessions == []
