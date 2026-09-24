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
from jdlib.persistence.strategies.rls import install_rls, verify_rls
from jdlib.persistence.strategies.shared import SharedSchemaStrategy
from tests.integration.rls_support import APP_PASSWORD, APP_ROLE, run_rls_ddl
from tests.support.invoice import Invoice

BYPASS_ROLE = "jdlib_rls_bypass"
TENANT_SCHEMA = "jt_test"
MISSING_ROLE = "jdlib_rls_missing"


def _async_url(postgres_url: str) -> str:
    return (
        sa.engine.make_url(postgres_url)
        .set(drivername="postgresql+asyncpg")
        .render_as_string(hide_password=False)
    )


def _app_url(postgres_url: str) -> URL:
    return sa.engine.make_url(postgres_url).set(
        drivername="postgresql+asyncpg", username=APP_ROLE, password=APP_PASSWORD
    )


def _bound_engine(postgres_url: str, *, url: URL | None = None) -> AsyncEngine:
    return create_async_engine(
        url or _async_url(postgres_url),
        connect_args={"server_settings": {"search_path": TENANT_SCHEMA}},
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


async def test_shared_schema_strategy_rebinds_tenant_setting_per_transaction(
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
                    sa.text(
                        f'SELECT count(*) FROM "{TENANT_SCHEMA}".invoices '
                        "WHERE tenant_id = :tenant_id"
                    ),
                    {"tenant_id": tenant_a},
                )
            ).scalar_one()
            assert after_commit == 2
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


async def test_shared_setting_is_unset_after_close(
    rls_engine: AsyncEngine, postgres_url: str
):
    tenant_a = uuid.uuid4()
    await _seed(rls_engine, [(tenant_a, "A-CLOSE")])
    app_engine = create_async_engine(_app_url(postgres_url), pool_size=1, max_overflow=0)
    strategy = SharedSchemaStrategy(
        app_engine, schema=TENANT_SCHEMA, rls=RlsConfig(enabled=True, app_role=APP_ROLE)
    )
    try:
        session = await strategy.session(_tenant(tenant_a))
        assert await _scoped_ids(session) == [tenant_a]
        await session.close()
        async with app_engine.connect() as connection:
            value = (
                await connection.execute(
                    sa.text("SELECT current_setting('app.tenant_id', true)")
                )
            ).scalar_one()
            assert not value
            count = (
                await connection.execute(
                    sa.text(f'SELECT count(*) FROM "{TENANT_SCHEMA}".invoices')
                )
            ).scalar_one()
            assert count == 0
    finally:
        await app_engine.dispose()


async def test_install_rls_emits_policies_and_verifies(
    rls_app_role: str, postgres_url: str
):
    engine = _bound_engine(postgres_url)
    try:
        await install_rls(engine, metadata=TenantBase.metadata, app_role=APP_ROLE)
        await verify_rls(engine, APP_ROLE, metadata=TenantBase.metadata)
    finally:
        await engine.dispose()


async def test_verify_rls_rejects_missing_policy(rls_app_role: str, postgres_url: str):
    engine = _bound_engine(postgres_url)
    try:
        await install_rls(engine, metadata=TenantBase.metadata, app_role=APP_ROLE)
        await run_rls_ddl(
            engine,
            lambda sync: sync.execute(sa.text("DROP POLICY tenant_isolation ON invoices")),
        )
        with pytest.raises(StrategyCapabilityError, match="policy"):
            await verify_rls(engine, APP_ROLE, metadata=TenantBase.metadata)
    finally:
        await engine.dispose()


async def test_verify_rls_rejects_unforced_table(rls_app_role: str, postgres_url: str):
    engine = _bound_engine(postgres_url)
    try:
        await install_rls(engine, metadata=TenantBase.metadata, app_role=APP_ROLE)
        await run_rls_ddl(
            engine,
            lambda sync: sync.execute(
                sa.text("ALTER TABLE invoices NO FORCE ROW LEVEL SECURITY")
            ),
        )
        with pytest.raises(StrategyCapabilityError, match="forced"):
            await verify_rls(engine, APP_ROLE, metadata=TenantBase.metadata)
    finally:
        await engine.dispose()


async def test_verify_rls_rejects_bypassing_role(rls_app_role: str, postgres_url: str):
    engine = _bound_engine(postgres_url)
    try:
        await install_rls(engine, metadata=TenantBase.metadata, app_role=APP_ROLE)
        async with engine.begin() as connection:
            await connection.execute(
                sa.text(
                    f"DO $$ BEGIN IF NOT EXISTS "
                    f"(SELECT FROM pg_roles WHERE rolname = '{BYPASS_ROLE}') "
                    f"THEN CREATE ROLE {BYPASS_ROLE} LOGIN PASSWORD '{APP_PASSWORD}' BYPASSRLS; "
                    "END IF; END $$;"
                )
            )
        with pytest.raises(StrategyCapabilityError, match="bypass"):
            await verify_rls(engine, BYPASS_ROLE, metadata=TenantBase.metadata)
    finally:
        await engine.dispose()


async def test_verify_rls_rejects_missing_and_superuser_roles(
    rls_app_role: str, postgres_url: str
):
    engine = _bound_engine(postgres_url)
    try:
        await install_rls(engine, metadata=TenantBase.metadata, app_role=APP_ROLE)
        await verify_rls(engine, APP_ROLE, metadata=TenantBase.metadata)
        with pytest.raises(StrategyCapabilityError, match="does not exist"):
            await verify_rls(engine, MISSING_ROLE, metadata=TenantBase.metadata)
        superuser = sa.engine.make_url(postgres_url).username
        assert superuser is not None
        with pytest.raises(StrategyCapabilityError, match="bypass"):
            await verify_rls(engine, superuser, metadata=TenantBase.metadata)
    finally:
        await engine.dispose()
