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
from jdlib.errors import AuthorizationError, UnscopedBulkOperation, UnscopedRawSql
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


def _privilege(capability: str = "platform.raw_sql") -> PrivilegeContext:
    return PrivilegeContext(
        kind=PrivilegeKind.OPERATOR,
        capability=capability,
        justification="ticket",
        actor=Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4()),
        issued_at=datetime.now(UTC),
        expires_at=None,
    )


class _RecordingAuditor:
    def __init__(self) -> None:
        self.records: list[tuple[RawSqlMode, str | None, uuid.UUID, str]] = []

    async def record_raw_sql(
        self, *, mode: RawSqlMode, capability: str | None, tenant_id: uuid.UUID, sql: str
    ) -> None:
        self.records.append((mode, capability, tenant_id, sql))


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


def _tenant_session(
    context: TenantContext,
    stub: _StubAsyncSession,
    auditor: _RecordingAuditor | None = None,
) -> TenantSession:
    return TenantSession(cast(Any, stub), context, auditor=auditor)


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
    auditor = _RecordingAuditor()
    session = _tenant_session(_context(_privilege()), stub, auditor)
    with context_scope(_context()):
        result = await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    assert result is stub.result
    assert len(stub.executed) == 1
    assert auditor.records == [
        (RawSqlMode.PRIVILEGED, "platform.raw_sql", TENANT_ID, "SELECT 1")
    ]


async def test_tenant_raw_sql_requires_tenant_bound_statement() -> None:
    stub = _StubAsyncSession()
    auditor = _RecordingAuditor()
    session = _tenant_session(_context(_privilege("tenant.raw_sql")), stub, auditor)
    with context_scope(_context()), pytest.raises(UnscopedRawSql):
        await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    assert stub.executed == []
    assert auditor.records == []


async def test_platform_raw_sql_accepts_unscoped_statement() -> None:
    stub = _StubAsyncSession()
    auditor = _RecordingAuditor()
    session = _tenant_session(_context(_privilege("platform.raw_sql")), stub, auditor)
    with context_scope(_context()):
        result = await session.raw_sql(sa.text("SELECT 1"), mode=RawSqlMode.PRIVILEGED)
    assert result is stub.result
    assert len(stub.executed) == 1
    assert auditor.records == [
        (RawSqlMode.PRIVILEGED, "platform.raw_sql", TENANT_ID, "SELECT 1")
    ]
