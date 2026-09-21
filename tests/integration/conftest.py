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
    from tests.support.invoice import Invoice  # noqa: F401

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
