from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession, create_async_engine

from jdlib.config import RlsConfig
from jdlib.context import TenantRecord
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.errors import StrategyCapabilityError
from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.rls import emit_rls_policies, verify_rls
from jdlib.persistence.strategies.shared import SharedSchemaStrategy
from tests.support.invoice import Invoice

APP_ROLE = "jdlib_rls_app"
APP_PASSWORD = "rls-test"
TENANT_SCHEMA = "jt_test"
MISSING_ROLE = "jdlib_rls_missing"


def _app_url(postgres_url: str) -> URL:
    return sa.engine.make_url(postgres_url).set(
        drivername="postgresql+asyncpg", username=APP_ROLE, password=APP_PASSWORD
    )


def _tenant(tenant_id: uuid.UUID) -> TenantRecord:
    return TenantRecord(
        id=tenant_id,
        slug=f"rls-{tenant_id.hex[:8]}",
        status=TenantStatus.ACTIVE,
        strategy=PlacementStrategy.SHARED,
    )


async def _seed(engine: AsyncEngine, rows: list[tuple[uuid.UUID, str]]) -> None:
    async with engine.begin() as connection:
        await connection.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
        await connection.execute(
            sa.insert(Invoice.__table__),
            [
                {"tenant_id": tenant_id, "id": uuid.uuid4(), "number": number}
                for tenant_id, number in rows
            ],
        )


async def _scoped_ids(session: AsyncConnection | AsyncSession) -> list[uuid.UUID]:
    result = await session.execute(
        sa.text(f'SELECT tenant_id FROM "{TENANT_SCHEMA}".invoices')
    )
    return list(result.scalars().all())


@pytest.fixture()
async def rls_engine(async_engine: AsyncEngine, postgres_url: str) -> AsyncEngine:
    async with async_engine.begin() as connection:
        await connection.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
        await connection.execute(
            sa.text(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') "
                f"THEN CREATE ROLE {APP_ROLE} LOGIN PASSWORD '{APP_PASSWORD}' NOBYPASSRLS; "
                "END IF; END $$;"
            )
        )
        await connection.execute(sa.text(f'GRANT USAGE ON SCHEMA "{TENANT_SCHEMA}" TO {APP_ROLE}'))
        await connection.execute(
            sa.text(
                f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA '
                f'"{TENANT_SCHEMA}" TO {APP_ROLE}'
            )
        )
        await connection.execute(
            sa.text(
                f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "{TENANT_SCHEMA}" TO {APP_ROLE}'
            )
        )
        await connection.run_sync(
            lambda sync: emit_rls_policies(
                sync, metadata=TenantBase.metadata, app_role=APP_ROLE
            )
        )
    yield async_engine


async def test_rls_unset_role_sees_no_rows_and_cannot_insert(
    rls_engine: AsyncEngine, postgres_url: str
):
    tenant_a = uuid.uuid4()
    await _seed(rls_engine, [(tenant_a, "A-UNSET")])
    app_engine = create_async_engine(_app_url(postgres_url))
    try:
        async with app_engine.connect() as connection:
            count = (
                await connection.execute(
                    sa.text(f'SELECT count(*) FROM "{TENANT_SCHEMA}".invoices')
                )
            ).scalar_one()
            assert count == 0
        async with app_engine.connect() as connection:
            with pytest.raises(sa.exc.ProgrammingError):
                await connection.execute(
                    sa.text(
                        f'INSERT INTO "{TENANT_SCHEMA}".invoices (tenant_id, id, number) '
                        "VALUES (:tenant_id, gen_random_uuid(), 'X')"
                    ),
                    {"tenant_id": tenant_a},
                )
            await connection.rollback()
    finally:
        await app_engine.dispose()


async def test_tenant_setting_scopes_rows_to_transaction(
    rls_engine: AsyncEngine, postgres_url: str
):
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    await _seed(rls_engine, [(tenant_a, "A-SCOPED"), (tenant_b, "B-SCOPED")])
    app_engine = create_async_engine(_app_url(postgres_url))
    try:
        async with app_engine.connect() as connection:
            await connection.execute(
                sa.text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
                {"tenant_id": str(tenant_a)},
            )
            assert await _scoped_ids(connection) == [tenant_a]
            await connection.execute(
                sa.text(
                    f'INSERT INTO "{TENANT_SCHEMA}".invoices (tenant_id, id, number, status) '
                    "VALUES (:tenant_id, gen_random_uuid(), :number, 'draft')"
                ),
                {"tenant_id": tenant_a, "number": "A-SCOPED-NEW"},
            )
            await connection.commit()
        async with app_engine.connect() as connection:
            assert await _scoped_ids(connection) == []
    finally:
        await app_engine.dispose()


async def test_shared_schema_strategy_binds_tenant_setting_to_transaction(
    rls_engine: AsyncEngine, postgres_url: str
):
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    await _seed(rls_engine, [(tenant_a, "A-UOW"), (tenant_b, "B-UOW")])
    app_engine = create_async_engine(_app_url(postgres_url))
    strategy = SharedSchemaStrategy(
        app_engine, schema=TENANT_SCHEMA, rls=RlsConfig(enabled=True, app_role=APP_ROLE)
    )
    try:
        session = await strategy.session(_tenant(tenant_a))
        try:
            assert await _scoped_ids(session) == [tenant_a]
            await session.execute(
                sa.text(
                    f'INSERT INTO "{TENANT_SCHEMA}".invoices (tenant_id, id, number, status) '
                    "VALUES (:tenant_id, gen_random_uuid(), :number, 'draft')"
                ),
                {"tenant_id": tenant_a, "number": "A-UOW-NEW"},
            )
            await session.commit()
            after_commit = (
                await session.execute(
                    sa.text(f'SELECT count(*) FROM "{TENANT_SCHEMA}".invoices')
                )
            ).scalar_one()
            assert after_commit == 0
        finally:
            await session.close()
        other = await strategy.session(_tenant(tenant_b))
        try:
            assert await _scoped_ids(other) == [tenant_b]
            with pytest.raises(sa.exc.ProgrammingError):
                await other.execute(
                    sa.text(
                        f'INSERT INTO "{TENANT_SCHEMA}".invoices (tenant_id, id, number, status) '
                        "VALUES (:tenant_id, gen_random_uuid(), :number, 'draft')"
                    ),
                    {"tenant_id": tenant_a, "number": "A-CROSS"},
                )
            await other.rollback()
        finally:
            await other.close()
    finally:
        await app_engine.dispose()


async def test_verify_rls_rejects_bypassing_and_missing_roles(
    rls_engine: AsyncEngine, postgres_url: str
):
    app_engine = create_async_engine(_app_url(postgres_url))
    try:
        await verify_rls(app_engine, APP_ROLE)
        with pytest.raises(StrategyCapabilityError):
            await verify_rls(app_engine, MISSING_ROLE)
        superuser = sa.engine.make_url(postgres_url).username
        assert superuser is not None
        with pytest.raises(StrategyCapabilityError):
            await verify_rls(rls_engine, superuser)
    finally:
        await app_engine.dispose()
