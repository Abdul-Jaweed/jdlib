import uuid
from datetime import UTC, datetime
from typing import Any, cast

import pytest
import sqlalchemy as sa

from jdlib.context import (
    Principal,
    PrincipalKind,
    PrivilegeContext,
    PrivilegeKind,
    TenantContext,
    context_scope,
)
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import AuthorizationError, UnscopedBulkOperation
from jdlib.persistence.rawsql import RawSqlMode
from jdlib.persistence.session import TenantSession
from tests.support.invoice import Invoice

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


def _privilege() -> PrivilegeContext:
    return PrivilegeContext(
        kind=PrivilegeKind.OPERATOR,
        capability="tenant.raw_sql",
        justification="ticket",
        actor=Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4()),
        issued_at=datetime.now(UTC),
        expires_at=None,
    )


class _StubAsyncSession:
    def __init__(self) -> None:
        self.sync_session = sa.orm.Session()
        self.bind = sa.create_engine("postgresql+psycopg://")
        self.result: Any = object()
        self.executed: list[sa.Executable] = []

    async def execute(self, statement: sa.Executable, params: object = None) -> Any:
        self.executed.append(statement)
        return self.result


class _ExecutingStubAsyncSession(_StubAsyncSession):
    async def execute(self, statement: sa.Executable, params: object = None) -> Any:
        self.executed.append(statement)
        return self.sync_session.execute(statement, params)


def _tenant_session(context: TenantContext, stub: _StubAsyncSession) -> TenantSession:
    return TenantSession(cast(Any, stub), context)


async def test_from_statement_wrapped_insert_rejected() -> None:
    stub = _ExecutingStubAsyncSession()
    session = _tenant_session(_context(), stub)
    statement = sa.select(Invoice).from_statement(sa.insert(Invoice).returning(Invoice))
    with pytest.raises(UnscopedBulkOperation):
        await session.execute(statement)


async def test_privileged_raw_sql_rejects_without_session_privilege() -> None:
    stub = _StubAsyncSession()
    session = _tenant_session(_context(), stub)
    with context_scope(_context(_privilege())), pytest.raises(AuthorizationError):
        await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    assert stub.executed == []


async def test_privileged_raw_sql_accepts_session_privilege() -> None:
    stub = _StubAsyncSession()
    session = _tenant_session(_context(_privilege()), stub)
    with context_scope(_context()):
        result = await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    assert result is stub.result
    assert len(stub.executed) == 1
