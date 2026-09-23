from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from jdlib.context import Principal, PrincipalKind, TenantContext, TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.errors import PoolCapacityError
from jdlib.migrations.runner import MigrationRunner
from jdlib.models.org import Organization
from jdlib.persistence.secrets import MemorySecretProvider
from jdlib.persistence.session import TenantSession
from jdlib.persistence.strategies.database import DatabasePerTenantStrategy
from jdlib.persistence.strategies.deprovision import DeprovisionMode


def _async_dsn(url: str) -> str:
    return url.replace("+psycopg", "+asyncpg")


def _tenant_dsn(url: str, database: str) -> str:
    parsed = sa.engine.make_url(_async_dsn(url)).set(database=database)
    return parsed.render_as_string(hide_password=False)


def _record(handle: str) -> TenantRecord:
    return TenantRecord(
        id=uuid.uuid4(),
        slug=f"slug-{uuid.uuid4().hex[:8]}",
        status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.DATABASE,
        target_handle=handle,
    )


def _context(tenant: TenantRecord) -> TenantContext:
    return TenantContext(
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        strategy=PlacementStrategy.DATABASE,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
    )


async def _database_exists(admin_dsn: str, name: str) -> bool:
    engine = create_async_engine(admin_dsn)
    try:
        async with engine.connect() as connection:
            found = await connection.execute(
                sa.text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": name},
            )
            return found.scalar_one_or_none() is not None
    finally:
        await engine.dispose()


@pytest.fixture()
async def make_strategy(
    postgres_url: str,
) -> AsyncIterator[Callable[..., DatabasePerTenantStrategy]]:
    created: list[DatabasePerTenantStrategy] = []

    def factory(
        *, secrets: dict[str, str], max_targets: int = 32
    ) -> DatabasePerTenantStrategy:
        strategy = DatabasePerTenantStrategy(
            admin_dsn=_async_dsn(postgres_url),
            secrets=MemorySecretProvider(secrets),
            runner=MigrationRunner(postgres_url),
            max_targets=max_targets,
        )
        created.append(strategy)
        return strategy

    yield factory
    for strategy in created:
        await strategy.dispose()
        await strategy.dispose()


async def test_provision_migrate_deprovision_second_database(postgres_url, make_strategy):
    admin_dsn = _async_dsn(postgres_url)
    database = f"jd_{uuid.uuid4().hex[:12]}"
    handle = f"db-{uuid.uuid4().hex[:8]}"
    dsn = _tenant_dsn(postgres_url, database)
    strategy = make_strategy(secrets={handle: dsn})
    tenant = _record(handle)
    assert not await _database_exists(admin_dsn, database)

    await strategy.provision(tenant)
    await strategy.provision(tenant)
    assert await _database_exists(admin_dsn, database)

    runner = MigrationRunner(postgres_url)
    await strategy.migrate(tenant, runner)
    assert runner.tenant_version_url(dsn, "public") == "0001_tenant_baseline"

    session = await strategy.session(tenant)
    try:
        scoped = TenantSession(session, _context(tenant))
        organization = Organization(name="Acme", slug="acme")
        await scoped.add(organization)
        await scoped.flush()
        organization_id = organization.id
        await scoped.commit()
    finally:
        await session.close()

    session = await strategy.session(tenant)
    try:
        scoped = TenantSession(session, _context(tenant))
        stored = await scoped.get(Organization, organization_id)
        assert stored is not None
        assert stored.name == "Acme"
    finally:
        await session.close()

    await strategy.deprovision(tenant, DeprovisionMode.PURGE)
    assert not await _database_exists(admin_dsn, database)
    await strategy.deprovision(tenant, DeprovisionMode.PURGE)
    assert not await _database_exists(admin_dsn, database)


async def test_pool_cap_never_disposes_checked_out_pool(postgres_url, make_strategy):
    admin_dsn = _async_dsn(postgres_url)
    database_a = f"jd_{uuid.uuid4().hex[:12]}"
    handle_a = f"db-{uuid.uuid4().hex[:8]}"
    handle_b = f"db-{uuid.uuid4().hex[:8]}"
    dsn_a = _tenant_dsn(postgres_url, database_a)
    dsn_b = _tenant_dsn(postgres_url, f"jd_{uuid.uuid4().hex[:12]}")
    strategy = make_strategy(secrets={handle_a: dsn_a, handle_b: dsn_b}, max_targets=1)
    tenant_a = _record(handle_a)
    await strategy.provision(tenant_a)

    session_a = await strategy.session(tenant_a)
    await session_a.execute(sa.text("SELECT 1"))
    with pytest.raises(PoolCapacityError):
        await strategy.session(_record(handle_b))
    await session_a.close()

    session_b = await strategy.session(_record(handle_b))
    await session_b.close()

    await strategy.deprovision(tenant_a, DeprovisionMode.PURGE)
    assert not await _database_exists(admin_dsn, database_a)
