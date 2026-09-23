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


def _record(handle: str) -> TenantRecord:
    return TenantRecord(
        id=uuid.uuid4(),
        slug=handle,
        status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.SCHEMA,
        target_handle=handle,
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


class _Runner:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        dsn = self._engine.url.render_as_string(hide_password=False)
        sync_engine = create_engine(dsn.replace("+asyncpg", "+psycopg"))
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


async def test_two_schemas_are_isolated(async_engine):
    strategy = SchemaPerTenantStrategy(async_engine, _Runner(async_engine))
    tenant_a = _record(f"t_{uuid.uuid4().hex[:10]}")
    tenant_b = _record(f"t_{uuid.uuid4().hex[:10]}")
    for tenant in (tenant_a, tenant_b):
        await strategy.provision(tenant)
        await strategy.migrate(tenant, _Runner(async_engine))
    session_a = TenantSession(await strategy.session(tenant_a), _context(tenant_a.id))
    session_b = TenantSession(await strategy.session(tenant_b), _context(tenant_b.id))
    try:
        await session_a.add(Invoice(number="INV-A"))
        await session_a.flush()
        invoice_id = (await session_a.execute(sa.select(Invoice.id))).scalar_one()
        assert await session_b.get(Invoice, invoice_id) is None
        assert [row.number for row in (await session_b.execute(sa.select(Invoice))).scalars()] == []
    finally:
        await session_a.close()
        await session_b.close()


async def test_deprovision_purge_drops_schema(async_engine):
    strategy = SchemaPerTenantStrategy(async_engine, _Runner(async_engine))
    tenant = _record(f"t_{uuid.uuid4().hex[:10]}")
    handle = str(tenant.target_handle)
    await strategy.provision(tenant)
    assert await _schema_exists(async_engine, handle)
    await strategy.deprovision(tenant, DeprovisionMode.ARCHIVE)
    assert await _schema_exists(async_engine, handle)
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
        tenant = _record(f"t_{uuid.uuid4().hex[:10]}")
        await strategy.provision(tenant)
        session = await strategy.session(tenant)
        await session.commit()
        await session.close()
        async with engine.connect() as connection:
            search_path = (await connection.execute(sa.text("SHOW search_path"))).scalar_one()
        assert tenant.target_handle not in search_path
    finally:
        await engine.dispose()
