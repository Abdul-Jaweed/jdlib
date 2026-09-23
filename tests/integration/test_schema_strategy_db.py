from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from jdlib.context import Principal, PrincipalKind, TenantContext, TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.models.base import TenantBase
from jdlib.persistence.session import TenantSession
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from jdlib.persistence.strategies.schema import SchemaPerTenantStrategy
from tests.support.invoice import Invoice


def _tenant() -> TenantRecord:
    return TenantRecord(
        id=uuid.uuid4(),
        slug=f"slug-{uuid.uuid4().hex[:8]}",
        status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.SCHEMA,
        target_handle=f"t_{uuid.uuid4().hex[:10]}",
    )


def _context(tenant_id: uuid.UUID) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug="schema",
        strategy=PlacementStrategy.SCHEMA,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
    )


def _sync_dsn(dsn: str) -> str:
    if dsn.startswith("postgresql://"):
        dsn = dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    return dsn.replace("+asyncpg", "+psycopg")


class _Runner:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        dsn = self._engine.url.render_as_string(hide_password=False)
        sync_engine = create_engine(_sync_dsn(dsn))
        try:
            with sync_engine.begin() as connection:
                connection.exec_driver_sql(f'SET search_path TO "{schema}"')
                TenantBase.metadata.create_all(connection)
        finally:
            sync_engine.dispose()


async def _schema_exists(engine: AsyncEngine, name: str) -> bool:
    async with engine.connect() as connection:
        found = await connection.execute(
            sa.text("SELECT 1 FROM pg_namespace WHERE nspname = :name"), {"name": name}
        )
        return found.scalar_one_or_none() is not None


async def _row_count(engine: AsyncEngine, schema: str) -> int:
    async with engine.connect() as connection:
        result = await connection.execute(sa.text(f'SELECT count(*) FROM "{schema}".invoices'))
        return int(result.scalar_one())


async def _provision(
    strategy: SchemaPerTenantStrategy, engine: AsyncEngine, tenant: TenantRecord
) -> None:
    await strategy.provision(tenant)
    await strategy.migrate(tenant, _Runner(engine))


async def test_two_schemas_are_isolated(async_engine):
    strategy = SchemaPerTenantStrategy(async_engine, _Runner(async_engine))
    tenant_a, tenant_b = _tenant(), _tenant()
    handle_a, handle_b = str(tenant_a.target_handle), str(tenant_b.target_handle)
    assert tenant_a.slug != tenant_a.target_handle
    assert tenant_b.slug != tenant_b.target_handle
    await _provision(strategy, async_engine, tenant_a)
    await _provision(strategy, async_engine, tenant_b)
    raw_a = await strategy.session(tenant_a)
    raw_b = await strategy.session(tenant_b)
    try:
        current_a = (await raw_a.execute(sa.text("SELECT current_schema()"))).scalar_one()
        current_b = (await raw_b.execute(sa.text("SELECT current_schema()"))).scalar_one()
        assert current_a == handle_a
        assert current_b == handle_b
        session_a = TenantSession(raw_a, _context(tenant_a.id))
        session_b = TenantSession(raw_b, _context(tenant_b.id))
        await session_a.add(Invoice(number="INV-A"))
        await session_a.flush()
        invoice_id = (await session_a.execute(sa.select(Invoice.id))).scalar_one()
        await session_a.commit()
        assert await session_b.get(Invoice, invoice_id) is None
        assert [row.number for row in (await session_b.execute(sa.select(Invoice))).scalars()] == []
    finally:
        await raw_a.close()
        await raw_b.close()
    assert await _row_count(async_engine, handle_a) == 1
    assert await _row_count(async_engine, handle_b) == 0


async def test_search_path_survives_rollback(async_engine):
    strategy = SchemaPerTenantStrategy(async_engine, _Runner(async_engine))
    tenant_a, tenant_b = _tenant(), _tenant()
    handle_a, handle_b = str(tenant_a.target_handle), str(tenant_b.target_handle)
    await _provision(strategy, async_engine, tenant_a)
    await _provision(strategy, async_engine, tenant_b)
    raw = await strategy.session(tenant_a)
    try:
        session = TenantSession(raw, _context(tenant_a.id))
        await session.add(Invoice(number="INV-ROLLBACK"))
        await session.flush()
        await session.rollback()
        current = (await raw.execute(sa.text("SELECT current_schema()"))).scalar_one()
        assert current == handle_a
        await session.add(Invoice(number="INV-RECOVERED"))
        await session.commit()
    finally:
        await raw.close()
    assert await _row_count(async_engine, handle_a) == 1
    assert await _row_count(async_engine, handle_b) == 0


async def test_provision_and_purge_are_idempotent(async_engine):
    strategy = SchemaPerTenantStrategy(async_engine, _Runner(async_engine))
    tenant = _tenant()
    handle = str(tenant.target_handle)
    await strategy.provision(tenant)
    await strategy.provision(tenant)
    assert await _schema_exists(async_engine, handle)
    await strategy.deprovision(tenant, DeprovisionMode.ARCHIVE)
    assert await _schema_exists(async_engine, handle)
    await strategy.deprovision(tenant, DeprovisionMode.PURGE)
    assert not await _schema_exists(async_engine, handle)
    await strategy.deprovision(tenant, DeprovisionMode.PURGE)
    assert not await _schema_exists(async_engine, handle)


async def test_committed_search_path_is_reset_on_checkin(postgres_url):
    engine = create_async_engine(
        postgres_url.replace("postgresql+psycopg", "postgresql+asyncpg"),
        pool_size=1,
        max_overflow=0,
    )
    try:
        strategy = SchemaPerTenantStrategy(engine, _Runner(engine))
        tenant = _tenant()
        await strategy.provision(tenant)
        session = await strategy.session(tenant)
        await session.execute(sa.text("SELECT 1"))
        await session.commit()
        await session.close()
        async with engine.connect() as connection:
            search_path = (await connection.execute(sa.text("SHOW search_path"))).scalar_one()
        assert tenant.target_handle not in search_path
    finally:
        await engine.dispose()
