from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from jdlib.config import RlsConfig
from jdlib.context import TenantRecord
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import CrossTenantReferenceError, UnscopedBulkOperation
from jdlib.migrations.runner import MigrationRunner
from jdlib.models.base import TenantBase
from jdlib.persistence.repository import TenantRepository
from jdlib.persistence.secrets import MemorySecretProvider
from jdlib.persistence.session import TenantSession
from jdlib.persistence.strategies.base import IsolationStrategy
from jdlib.persistence.strategies.database import DatabasePerTenantStrategy
from jdlib.persistence.strategies.deprovision import DeprovisionMode
from jdlib.persistence.strategies.rls import install_rls
from jdlib.persistence.strategies.schema import SchemaPerTenantStrategy
from jdlib.persistence.strategies.shared import SharedSchemaStrategy
from tests.integration.strategy_support import (
    TENANT_SCHEMA,
    SchemaRunner,
    async_url,
    database_dsn,
    database_handle,
    database_name,
    provision_schema,
    schema_handle,
    tenant_context,
    tenant_record,
)
from tests.support.invoice import Invoice

RLS_APP_ROLE = "jdlib_rls_app"
RLS_APP_PASSWORD = "rls-test"
STRATEGIES = ("shared", "shared-rls", "schema", "database")

_ROLE_DDL = (
    f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{RLS_APP_ROLE}') "
    f"THEN CREATE ROLE {RLS_APP_ROLE} LOGIN PASSWORD '{RLS_APP_PASSWORD}' NOBYPASSRLS; "
    "END IF; END $$;"
)


@dataclass
class _Matrix:
    strategy: IsolationStrategy
    tenant_a: TenantRecord
    tenant_b: TenantRecord

    async def scoped(self, tenant: TenantRecord) -> TenantSession:
        session = await self.strategy.session(tenant)
        return TenantSession(session, tenant_context(tenant))


def _bound_engine(
    postgres_url: str, *, username: str | None = None, password: str | None = None
) -> AsyncEngine:
    url = sa.engine.make_url(async_url(postgres_url))
    if username is not None:
        url = url.set(username=username, password=password)
    return create_async_engine(
        url, connect_args={"server_settings": {"search_path": TENANT_SCHEMA}}
    )


async def _install_app_role(engine: AsyncEngine) -> bool:
    try:
        async with engine.begin() as connection:
            await connection.execute(sa.text(_ROLE_DDL))
            await connection.execute(
                sa.text(f'GRANT USAGE ON SCHEMA "{TENANT_SCHEMA}" TO {RLS_APP_ROLE}')
            )
            await connection.execute(
                sa.text(
                    f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA '
                    f'"{TENANT_SCHEMA}" TO {RLS_APP_ROLE}'
                )
            )
            await connection.execute(
                sa.text(
                    f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "{TENANT_SCHEMA}" '
                    f"TO {RLS_APP_ROLE}"
                )
            )
    except sa.exc.ProgrammingError:
        return False
    return True


@pytest.fixture(params=STRATEGIES)
async def matrix(request, async_engine, postgres_url):
    case = request.param
    cleanup: list[Callable[[], Awaitable[None]]] = []
    strategy: IsolationStrategy
    if case == "shared":
        engine = _bound_engine(postgres_url)
        cleanup.append(engine.dispose)
        strategy = SharedSchemaStrategy(engine, schema=TENANT_SCHEMA)
        tenant_a = tenant_record(PlacementStrategy.SHARED)
        tenant_b = tenant_record(PlacementStrategy.SHARED)
    elif case == "shared-rls":
        if not await _install_app_role(async_engine):
            pytest.skip("RLS app role is not installable")
        admin = _bound_engine(postgres_url)
        try:
            await install_rls(admin, metadata=TenantBase.metadata, app_role=RLS_APP_ROLE)
        finally:
            await admin.dispose()
        engine = _bound_engine(postgres_url, username=RLS_APP_ROLE, password=RLS_APP_PASSWORD)
        cleanup.append(engine.dispose)
        strategy = SharedSchemaStrategy(
            engine,
            schema=TENANT_SCHEMA,
            rls=RlsConfig(enabled=True, app_role=RLS_APP_ROLE),
        )
        tenant_a = tenant_record(PlacementStrategy.SHARED)
        tenant_b = tenant_record(PlacementStrategy.SHARED)
    elif case == "schema":
        strategy = SchemaPerTenantStrategy(async_engine, SchemaRunner(async_engine))
        tenant_a = tenant_record(PlacementStrategy.SCHEMA, handle=schema_handle())
        tenant_b = tenant_record(PlacementStrategy.SCHEMA, handle=schema_handle())
        await provision_schema(strategy, tenant_a, async_engine)
        await provision_schema(strategy, tenant_b, async_engine)
        cleanup.append(lambda: strategy.deprovision(tenant_a, DeprovisionMode.PURGE))
        cleanup.append(lambda: strategy.deprovision(tenant_b, DeprovisionMode.PURGE))
    else:
        handle_a, handle_b = database_handle(), database_handle()
        strategy = DatabasePerTenantStrategy(
            admin_dsn=async_url(postgres_url),
            secrets=MemorySecretProvider(
                {
                    handle_a: database_dsn(postgres_url, database_name()),
                    handle_b: database_dsn(postgres_url, database_name()),
                }
            ),
            runner=MigrationRunner(postgres_url),
        )
        tenant_a = tenant_record(PlacementStrategy.DATABASE, handle=handle_a)
        tenant_b = tenant_record(PlacementStrategy.DATABASE, handle=handle_b)
        runner = MigrationRunner(postgres_url)
        await strategy.provision(tenant_a)
        await strategy.migrate(tenant_a, runner)
        await strategy.provision(tenant_b)
        await strategy.migrate(tenant_b, runner)
        cleanup.append(lambda: strategy.deprovision(tenant_a, DeprovisionMode.PURGE))
        cleanup.append(lambda: strategy.deprovision(tenant_b, DeprovisionMode.PURGE))
        cleanup.append(strategy.dispose)
    try:
        yield _Matrix(strategy=strategy, tenant_a=tenant_a, tenant_b=tenant_b)
    finally:
        for step in cleanup:
            await step()


async def test_scoped_reads(matrix: _Matrix) -> None:
    async with await matrix.scoped(matrix.tenant_a) as session:
        repository = TenantRepository(session, Invoice)
        await repository.add(Invoice(number="A-READ-1"))
        await repository.add(Invoice(number="A-READ-2"))
        await session.commit()
    async with await matrix.scoped(matrix.tenant_b) as session:
        await TenantRepository(session, Invoice).add(Invoice(number="B-READ-1"))
        await session.commit()
    async with await matrix.scoped(matrix.tenant_a) as session:
        numbers = {
            invoice.number for invoice in await TenantRepository(session, Invoice).list()
        }
        assert numbers == {"A-READ-1", "A-READ-2"}
    async with await matrix.scoped(matrix.tenant_b) as session:
        numbers = {
            invoice.number for invoice in await TenantRepository(session, Invoice).list()
        }
        assert numbers == {"B-READ-1"}


async def test_cross_tenant_get_returns_none(matrix: _Matrix) -> None:
    other_id = uuid.uuid4()
    async with await matrix.scoped(matrix.tenant_b) as session:
        await session.add(Invoice(id=other_id, number="B-GET"))
        await session.commit()
    async with await matrix.scoped(matrix.tenant_b) as session:
        assert await session.get(Invoice, other_id) is not None
    async with await matrix.scoped(matrix.tenant_a) as session:
        assert await session.get(Invoice, other_id) is None


async def test_writes_are_stamped(matrix: _Matrix) -> None:
    invoice = Invoice(number="A-STAMP")
    async with await matrix.scoped(matrix.tenant_a) as session:
        await TenantRepository(session, Invoice).add(invoice)
        assert invoice.tenant_id == matrix.tenant_a.id


async def test_tenant_id_is_immutable(matrix: _Matrix) -> None:
    async with await matrix.scoped(matrix.tenant_a) as session:
        invoice = Invoice(number="A-IMMUTABLE")
        await session.add(invoice)
        await session.flush()
        invoice.tenant_id = matrix.tenant_b.id
        with pytest.raises(CrossTenantReferenceError):
            await session.flush()


async def test_unscoped_bulk_dml_rejected(matrix: _Matrix) -> None:
    async with await matrix.scoped(matrix.tenant_a) as session:
        with pytest.raises(UnscopedBulkOperation):
            await session.execute(sa.update(Invoice).values(status="paid"))


async def test_entity_less_count_is_scoped(matrix: _Matrix) -> None:
    async with await matrix.scoped(matrix.tenant_a) as session:
        await TenantRepository(session, Invoice).add(Invoice(number="A-COUNT"))
        await session.commit()
    async with await matrix.scoped(matrix.tenant_b) as session:
        repository = TenantRepository(session, Invoice)
        await repository.add(Invoice(number="B-COUNT-1"))
        await repository.add(Invoice(number="B-COUNT-2"))
        await session.commit()
    async with await matrix.scoped(matrix.tenant_a) as session:
        count = (
            await session.execute(sa.select(sa.func.count()).select_from(Invoice))
        ).scalar_one()
        assert count == 1
        assert await TenantRepository(session, Invoice).count() == 1
    async with await matrix.scoped(matrix.tenant_b) as session:
        count = (
            await session.execute(sa.select(sa.func.count()).select_from(Invoice))
        ).scalar_one()
        assert count == 2
        assert await TenantRepository(session, Invoice).count() == 2
