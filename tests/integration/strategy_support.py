from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from jdlib.context import Principal, PrincipalKind, TenantContext, TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.schema import SchemaPerTenantStrategy

TENANT_SCHEMA = "jt_test"


def async_url(url: str) -> str:
    return (
        sa.engine.make_url(url)
        .set(drivername="postgresql+asyncpg")
        .render_as_string(hide_password=False)
    )


def sync_url(url: str) -> str:
    return (
        sa.engine.make_url(url)
        .set(drivername="postgresql+psycopg")
        .render_as_string(hide_password=False)
    )


def schema_handle() -> str:
    return f"t_{uuid.uuid4().hex[:10]}"


def tenant_record(strategy: PlacementStrategy, *, handle: str | None = None) -> TenantRecord:
    return TenantRecord(
        id=uuid.uuid4(),
        slug=f"slug-{uuid.uuid4().hex[:8]}",
        status=TenantStatus.ACTIVE,
        strategy=strategy,
        target_handle=handle,
    )


def tenant_context(tenant: TenantRecord) -> TenantContext:
    return TenantContext(
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        strategy=tenant.strategy,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
    )


class SchemaRunner:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        sync_engine = create_engine(
            sync_url(self._engine.url.render_as_string(hide_password=False))
        )
        try:
            with sync_engine.begin() as connection:
                connection.exec_driver_sql(f'SET search_path TO "{schema}"')
                TenantBase.metadata.create_all(connection)
        finally:
            sync_engine.dispose()


async def provision_schema(
    strategy: SchemaPerTenantStrategy, tenant: TenantRecord, engine: AsyncEngine
) -> None:
    await strategy.provision(tenant)
    await strategy.migrate(tenant, SchemaRunner(engine))


async def schema_exists(engine: AsyncEngine, name: str) -> bool:
    async with engine.connect() as connection:
        found = await connection.execute(
            sa.text("SELECT 1 FROM pg_namespace WHERE nspname = :name"), {"name": name}
        )
        return found.scalar_one_or_none() is not None


async def row_count(engine: AsyncEngine, schema: str) -> int:
    async with engine.connect() as connection:
        result = await connection.execute(sa.text(f'SELECT count(*) FROM "{schema}".invoices'))
        return int(result.scalar_one())


def database_name() -> str:
    return f"jd_{uuid.uuid4().hex[:12]}"


def database_handle() -> str:
    return f"db-{uuid.uuid4().hex[:8]}"


def database_dsn(url: str, database: str) -> str:
    parsed = sa.engine.make_url(async_url(url)).set(database=database)
    return parsed.render_as_string(hide_password=False)


async def database_exists(admin_dsn: str, name: str) -> bool:
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
