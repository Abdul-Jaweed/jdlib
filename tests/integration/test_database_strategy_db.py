from __future__ import annotations

from collections.abc import AsyncIterator, Callable

import pytest
import sqlalchemy as sa

from jdlib.control.enums import PlacementStrategy
from jdlib.errors import PoolCapacityError
from jdlib.migrations.runner import MigrationRunner
from jdlib.models.org import Organization
from jdlib.persistence.secrets import MemorySecretProvider
from jdlib.persistence.session import TenantSession
from jdlib.persistence.strategies.database import DatabasePerTenantStrategy
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from tests.integration.strategy_support import (
    async_url,
    database_dsn,
    database_exists,
    database_handle,
    database_name,
    tenant_context,
    tenant_record,
)


@pytest.fixture()
async def make_strategy(
    postgres_url: str,
) -> AsyncIterator[Callable[..., DatabasePerTenantStrategy]]:
    created: list[DatabasePerTenantStrategy] = []

    def factory(
        *, secrets: dict[str, str], max_targets: int = 32
    ) -> DatabasePerTenantStrategy:
        strategy = DatabasePerTenantStrategy(
            admin_dsn=async_url(postgres_url),
            secrets=MemorySecretProvider(secrets),
            runner=MigrationRunner(postgres_url),
            max_targets=max_targets,
        )
        created.append(strategy)
        return strategy

    yield factory
    for strategy in created:
        await strategy.dispose()


async def test_provision_migrate_deprovision_second_database(postgres_url, make_strategy):
    admin_dsn = async_url(postgres_url)
    database = database_name()
    handle = database_handle()
    dsn = database_dsn(postgres_url, database)
    strategy = make_strategy(secrets={handle: dsn})
    tenant = tenant_record(PlacementStrategy.DATABASE, handle=handle)
    assert not await database_exists(admin_dsn, database)

    await strategy.provision(tenant)
    await strategy.provision(tenant)
    assert await database_exists(admin_dsn, database)

    runner = MigrationRunner(postgres_url)
    await strategy.migrate(tenant, runner)
    assert runner.tenant_version_url(dsn, "public") == "0001_tenant_baseline"

    session = await strategy.session(tenant)
    try:
        scoped = TenantSession(session, tenant_context(tenant))
        organization = Organization(name="Acme", slug="acme")
        await scoped.add(organization)
        await scoped.flush()
        organization_id = organization.id
        await scoped.commit()
    finally:
        await session.close()

    session = await strategy.session(tenant)
    try:
        scoped = TenantSession(session, tenant_context(tenant))
        stored = await scoped.get(Organization, organization_id)
        assert stored is not None
        assert stored.name == "Acme"
    finally:
        await session.close()

    await strategy.deprovision(tenant, DeprovisionMode.PURGE)
    assert not await database_exists(admin_dsn, database)
    await strategy.deprovision(tenant, DeprovisionMode.PURGE)
    assert not await database_exists(admin_dsn, database)


async def test_pool_cap_never_disposes_checked_out_pool(postgres_url, make_strategy):
    admin_dsn = async_url(postgres_url)
    database_a = database_name()
    handle_a = database_handle()
    handle_b = database_handle()
    dsn_a = database_dsn(postgres_url, database_a)
    dsn_b = database_dsn(postgres_url, database_name())
    strategy = make_strategy(secrets={handle_a: dsn_a, handle_b: dsn_b}, max_targets=1)
    tenant_a = tenant_record(PlacementStrategy.DATABASE, handle=handle_a)
    await strategy.provision(tenant_a)

    session_a = await strategy.session(tenant_a)
    await session_a.execute(sa.text("SELECT 1"))
    with pytest.raises(PoolCapacityError):
        await strategy.session(tenant_record(PlacementStrategy.DATABASE, handle=handle_b))
    await session_a.close()

    session_b = await strategy.session(
        tenant_record(PlacementStrategy.DATABASE, handle=handle_b)
    )
    await session_b.close()

    await strategy.deprovision(tenant_a, DeprovisionMode.PURGE)
    assert not await database_exists(admin_dsn, database_a)
