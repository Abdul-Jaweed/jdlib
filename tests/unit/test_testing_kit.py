from __future__ import annotations

import importlib.metadata
import importlib.util
import sys
import uuid
from collections.abc import Callable

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.audit import DatabaseAuditSink
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import CrossTenantReferenceError
from jdlib.testing import (
    assert_cross_tenant_write_rejected,
    assert_scoped_count,
    assert_tenant_isolated,
    assertions,
    pytest_plugin,
)


class _FakeControlSession:
    def __init__(self, *, flush_error: Exception | None = None) -> None:
        self.added: list[object] = []
        self.closed = False
        self.committed = False
        self._flush_error = flush_error

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        if self._flush_error is not None:
            raise self._flush_error

    async def commit(self) -> None:
        self.committed = True

    async def close(self) -> None:
        self.closed = True


class _Result:
    def __init__(self, count: int) -> None:
        self._count = count

    def scalar_one(self) -> int:
        return self._count


class _RawSession:
    def __init__(
        self,
        *,
        count: int = 0,
        entity: object | None = None,
        flush_error: Exception | None = None,
    ) -> None:
        self.count = count
        self.entity = entity
        self.flush_error = flush_error
        self.added: list[object] = []
        self.flushed = False
        self.committed = False
        self.closed = False


class _FakeTenantSession:
    def __init__(self, raw: _RawSession, context: TenantContext) -> None:
        self.raw = raw
        self.context = context

    async def __aenter__(self) -> _FakeTenantSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def add(self, obj: object) -> None:
        self.raw.added.append(obj)

    async def flush(self) -> None:
        self.raw.flushed = True
        for obj in self.raw.added:
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()
        if self.raw.flush_error is not None:
            raise self.raw.flush_error

    async def commit(self) -> None:
        self.raw.committed = True

    async def close(self) -> None:
        self.raw.closed = True

    async def execute(self, statement: object) -> _Result:
        return _Result(self.raw.count)

    async def get(self, model: type[object], entity_id: uuid.UUID) -> object | None:
        return self.raw.entity


class _Base(DeclarativeBase):
    pass


class _Model(_Base):
    __tablename__ = "fake_rows"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column()
    name: Mapped[str | None] = mapped_column(sa.Text)


def _context(slug: str = "acme") -> TenantContext:
    return TenantContext(
        tenant_id=uuid.uuid4(),
        tenant_slug=slug,
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
    )


def _factory(*raws: _RawSession) -> Callable[[], _RawSession]:
    iterator = iter(raws)
    return lambda: next(iterator)


def _use_fake_tenant_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assertions, "TenantSession", _FakeTenantSession)


async def test_database_sink_closes_owned_session_when_flush_fails():
    session = _FakeControlSession(flush_error=RuntimeError("flush failed"))
    sink = DatabaseAuditSink(lambda: session)

    with pytest.raises(RuntimeError, match="flush failed"):
        await sink.record(action="tenant.created", tenant_id=None, actor_id=None)

    assert session.closed
    assert not session.committed


async def test_scoped_count_passes_when_count_matches(monkeypatch):
    _use_fake_tenant_session(monkeypatch)

    await assert_scoped_count(_factory(_RawSession(count=2)), _context(), _Model, 2)


async def test_scoped_count_fails_when_count_differs(monkeypatch):
    _use_fake_tenant_session(monkeypatch)

    with pytest.raises(AssertionError, match="expected 2"):
        await assert_scoped_count(_factory(_RawSession(count=1)), _context(), _Model, 2)


async def test_tenant_isolated_passes_and_returns_b_row_id(monkeypatch):
    _use_fake_tenant_session(monkeypatch)
    b_raw = _RawSession()
    a_raw = _RawSession(count=0)
    context_a = _context()
    context_b = _context("globex")

    row_id = await assert_tenant_isolated(
        _factory(b_raw, a_raw), context_a, context_b, _Model, name="b"
    )

    assert b_raw.committed
    assert b_raw.closed
    assert a_raw.closed
    assert row_id == b_raw.added[0].id
    assert b_raw.added[0].tenant_id == context_b.tenant_id


async def test_tenant_isolated_fails_when_other_tenant_count_visible(monkeypatch):
    _use_fake_tenant_session(monkeypatch)

    with pytest.raises(AssertionError, match="sees 1"):
        await assert_tenant_isolated(
            _factory(_RawSession(), _RawSession(count=1)), _context(), _context(), _Model
        )


async def test_tenant_isolated_fails_when_other_tenant_row_gettable(monkeypatch):
    _use_fake_tenant_session(monkeypatch)

    with pytest.raises(AssertionError, match="can get"):
        await assert_tenant_isolated(
            _factory(_RawSession(), _RawSession(entity=object())),
            _context(),
            _context(),
            _Model,
        )


async def test_cross_tenant_write_rejected_passes_when_flush_raises(monkeypatch):
    _use_fake_tenant_session(monkeypatch)
    raw = _RawSession(flush_error=CrossTenantReferenceError("_Model.tenant_id", "a", "b"))
    context = _context()

    await assert_cross_tenant_write_rejected(_factory(raw), context, _Model, name="x")

    assert raw.added[0].tenant_id != context.tenant_id


async def test_cross_tenant_write_rejected_fails_when_flush_succeeds(monkeypatch):
    _use_fake_tenant_session(monkeypatch)

    with pytest.raises(AssertionError, match="flush accepted"):
        await assert_cross_tenant_write_rejected(_factory(_RawSession()), _context(), _Model)


def test_plugin_exposes_kit_fixtures():
    for name in (
        "jdlib_database_url",
        "jdlib_engine",
        "jdlib_models",
        "jdlib_schema",
        "jdlib_session_factory",
    ):
        assert callable(getattr(pytest_plugin, name))
    assert pytest_plugin.jdlib_test_models() == (
        "jdlib.models.org",
        "jdlib.models.settings",
        "jdlib.models.audit",
    )


def test_plugin_registered_as_pytest11_entry_point():
    entry_points = importlib.metadata.entry_points(group="pytest11")
    assert any(
        entry_point.name == "jdlib" and entry_point.value == "jdlib.testing.pytest_plugin"
        for entry_point in entry_points
    )


def test_plugin_imports_without_pytest_asyncio(monkeypatch):
    monkeypatch.setitem(sys.modules, "pytest_asyncio", None)
    spec = importlib.util.spec_from_file_location("jdlib_plugin_probe", pytest_plugin.__file__)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert callable(module.jdlib_engine)
    with pytest.raises(pytest.skip.Exception, match="pytest-asyncio"):
        module.jdlib_engine.__wrapped__()


class _FakeConnection:
    def __init__(self, statements: list[str]) -> None:
        self.statements = statements
        self.dialect = postgresql.dialect()

    async def execute(self, statement: object) -> None:
        self.statements.append(str(statement))

    async def run_sync(self, fn: object) -> None:
        return None


class _FakeBegin:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    async def __aenter__(self) -> _FakeConnection:
        return self._connection

    async def __aexit__(self, *exc: object) -> None:
        return None


class _FakeEngine:
    def __init__(self, *, fail_begin: bool = False) -> None:
        self.statements: list[str] = []
        self.disposed = False
        self._fail_begin = fail_begin

    def begin(self) -> _FakeBegin:
        if self._fail_begin:
            raise RuntimeError("connect failed")
        return _FakeBegin(_FakeConnection(self.statements))

    async def dispose(self) -> None:
        self.disposed = True


async def test_engine_fixture_disposes_when_setup_fails(monkeypatch):
    engine = _FakeEngine(fail_begin=True)
    monkeypatch.setattr(pytest_plugin, "create_async_engine", lambda *args, **kwargs: engine)
    iterator = pytest_plugin.jdlib_engine.__wrapped__(
        jdlib_database_url="postgresql://example/db",
        jdlib_schema="jdlib_test",
        jdlib_models=(),
    )
    with pytest.raises(RuntimeError, match="connect failed"):
        await anext(iterator)
    assert engine.disposed


async def test_engine_fixture_quotes_schema_with_dialect_preparer(monkeypatch):
    engine = _FakeEngine()
    monkeypatch.setattr(pytest_plugin, "create_async_engine", lambda *args, **kwargs: engine)
    iterator = pytest_plugin.jdlib_engine.__wrapped__(
        jdlib_database_url="postgresql://example/db",
        jdlib_schema='odd"name',
        jdlib_models=(),
    )
    await anext(iterator)
    assert engine.statements == ['CREATE SCHEMA IF NOT EXISTS "odd""name"']
    await anext(iterator, None)
    assert engine.disposed
