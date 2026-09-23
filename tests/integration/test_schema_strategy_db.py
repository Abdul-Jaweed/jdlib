from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from jdlib.context import TenantRecord
from jdlib.control.enums import PlacementStrategy
from jdlib.persistence.session import TenantSession
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from jdlib.persistence.strategies.schema import SchemaPerTenantStrategy
from tests.integration.strategy_support import (
    SchemaRunner,
    provision_schema,
    row_count,
    schema_exists,
    schema_handle,
    tenant_context,
    tenant_record,
)
from tests.support.invoice import Invoice


def _tenant() -> TenantRecord:
    return tenant_record(PlacementStrategy.SCHEMA, handle=schema_handle())


async def test_two_schemas_are_isolated(async_engine):
    strategy = SchemaPerTenantStrategy(async_engine, SchemaRunner(async_engine))
    tenant_a, tenant_b = _tenant(), _tenant()
    handle_a, handle_b = str(tenant_a.target_handle), str(tenant_b.target_handle)
    assert tenant_a.slug != tenant_a.target_handle
    assert tenant_b.slug != tenant_b.target_handle
    await provision_schema(strategy, tenant_a, async_engine)
    await provision_schema(strategy, tenant_b, async_engine)
    raw_a = await strategy.session(tenant_a)
    raw_b = await strategy.session(tenant_b)
    try:
        current_a = (await raw_a.execute(sa.text("SELECT current_schema()"))).scalar_one()
        current_b = (await raw_b.execute(sa.text("SELECT current_schema()"))).scalar_one()
        assert current_a == handle_a
        assert current_b == handle_b
        session_a = TenantSession(raw_a, tenant_context(tenant_a))
        session_b = TenantSession(raw_b, tenant_context(tenant_b))
        await session_a.add(Invoice(number="INV-A"))
        await session_a.flush()
        invoice_id = (await session_a.execute(sa.select(Invoice.id))).scalar_one()
        await session_a.commit()
        assert await session_b.get(Invoice, invoice_id) is None
        assert [row.number for row in (await session_b.execute(sa.select(Invoice))).scalars()] == []
    finally:
        await raw_a.close()
        await raw_b.close()
    assert await row_count(async_engine, handle_a) == 1
    assert await row_count(async_engine, handle_b) == 0


async def test_search_path_survives_rollback(async_engine):
    strategy = SchemaPerTenantStrategy(async_engine, SchemaRunner(async_engine))
    tenant_a, tenant_b = _tenant(), _tenant()
    handle_a, handle_b = str(tenant_a.target_handle), str(tenant_b.target_handle)
    await provision_schema(strategy, tenant_a, async_engine)
    await provision_schema(strategy, tenant_b, async_engine)
    raw = await strategy.session(tenant_a)
    try:
        session = TenantSession(raw, tenant_context(tenant_a))
        await session.add(Invoice(number="INV-ROLLBACK"))
        await session.flush()
        await session.rollback()
        current = (await raw.execute(sa.text("SELECT current_schema()"))).scalar_one()
        assert current == handle_a
        await session.add(Invoice(number="INV-RECOVERED"))
        await session.commit()
    finally:
        await raw.close()
    assert await row_count(async_engine, handle_a) == 1
    assert await row_count(async_engine, handle_b) == 0


async def test_provision_and_purge_are_idempotent(async_engine):
    strategy = SchemaPerTenantStrategy(async_engine, SchemaRunner(async_engine))
    tenant = _tenant()
    handle = str(tenant.target_handle)
    await strategy.provision(tenant)
    await strategy.provision(tenant)
    assert await schema_exists(async_engine, handle)
    await strategy.deprovision(tenant, DeprovisionMode.ARCHIVE)
    assert await schema_exists(async_engine, handle)
    await strategy.deprovision(tenant, DeprovisionMode.PURGE)
    assert not await schema_exists(async_engine, handle)
    await strategy.deprovision(tenant, DeprovisionMode.PURGE)
    assert not await schema_exists(async_engine, handle)


async def test_committed_search_path_is_reset_on_checkin(postgres_url):
    engine = create_async_engine(
        postgres_url.replace("postgresql+psycopg", "postgresql+asyncpg"),
        pool_size=1,
        max_overflow=0,
    )
    try:
        strategy = SchemaPerTenantStrategy(engine, SchemaRunner(engine))
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
