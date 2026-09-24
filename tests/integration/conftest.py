from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

CONTROL_SCHEMA = "jd_control"
TENANT_SCHEMA = "jt_test"


@pytest.fixture(scope="session")
def postgres_url() -> Iterator[str]:
    if url := os.environ.get("JDLIB_TEST_DATABASE_URL"):
        yield url
        return
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer("postgres:16", driver="psycopg") as container:
        yield container.get_connection_url()


@pytest.fixture(scope="session")
def control_engine(postgres_url: str) -> Iterator[Engine]:
    engine = sa.create_engine(postgres_url, future=True)
    with engine.begin() as connection:
        connection.exec_driver_sql('CREATE EXTENSION IF NOT EXISTS citext')
        connection.exec_driver_sql(f'CREATE SCHEMA IF NOT EXISTS "{CONTROL_SCHEMA}"')
        connection.exec_driver_sql(f'CREATE SCHEMA IF NOT EXISTS "{TENANT_SCHEMA}"')
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def control_metadata(control_engine: Engine) -> Iterator[None]:
    from jdlib.control.base import ControlBase
    from jdlib.control.models import Tenant  # noqa: F401

    ControlBase.metadata.create_all(control_engine)
    yield


@pytest.fixture()
async def async_engine(postgres_url: str):
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from jdlib.control.models import Tenant  # noqa: F401
    from jdlib.models import audit, org, settings  # noqa: F401
    from jdlib.models.base import TenantBase
    from tests.support.invoice import Invoice, LineItem  # noqa: F401

    engine = create_async_engine(
        postgres_url.replace("postgresql+psycopg", "postgresql+asyncpg")
    )
    async with engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{CONTROL_SCHEMA}"'))
        await connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{TENANT_SCHEMA}"'))
        await connection.execute(text(f'SET search_path TO "{TENANT_SCHEMA}"'))
        await connection.run_sync(TenantBase.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def session_factory(async_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    return async_sessionmaker(async_engine, expire_on_commit=False)


@pytest.fixture()
async def control_session_factory(async_engine, control_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from jdlib.control.base import ControlBase
    from jdlib.control.models import Tenant  # noqa: F401

    async with async_engine.begin() as connection:
        await connection.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}", public'))
        await connection.run_sync(ControlBase.metadata.create_all)
    return async_sessionmaker(async_engine, expire_on_commit=False)


# The RLS harness lives here, not in a test module, because two suites need the
# same schema: the isolation tests and the compliance collectors that observe it.
# A fixture defined in a test module cannot be imported and used as a parameter
# without shadowing the import, and a second copy of the harness would be a second
# schema to keep in step with the first.


@pytest.fixture()
async def rls_app_role(async_engine) -> str:
    from tests.integration.rls_support import ensure_rls_role

    return await ensure_rls_role(async_engine, TENANT_SCHEMA)


@pytest.fixture()
async def rls_engine(async_engine, rls_app_role: str):
    from tests.integration.rls_support import emit_tenant_policies, run_rls_ddl

    await run_rls_ddl(async_engine, lambda sync: emit_tenant_policies(sync, TENANT_SCHEMA))
    yield async_engine

# --- Integration layer: skip cleanly, never fail, when its infrastructure is absent --------
# Phase 1 hygiene. A missing Docker daemon means these tests are correct and UNRUN, which is a
# different statement from a broken build. pytest_collection_modifyitems is global, so the
# directory filter below is what keeps this from touching the unit layer.
def pytest_collection_modifyitems(config, items):
    from pathlib import Path

    from tests.support import infra_guard

    reason = infra_guard.docker_unavailable_reason()
    if reason is None:
        return
    here = Path(__file__).resolve().parent
    skip = pytest.mark.skip(reason=f"integration infrastructure unavailable: {reason}")
    for item in items:
        path = getattr(item, "path", None)
        if path is not None and here in Path(path).resolve().parents:
            item.add_marker(skip)
