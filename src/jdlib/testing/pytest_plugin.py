from __future__ import annotations

import importlib
import os
from collections.abc import AsyncIterator

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from jdlib.models.base import TenantBase

try:
    import pytest_asyncio
except ImportError:
    pytest_asyncio = None  # type: ignore[assignment]


def jdlib_test_models() -> tuple[str, ...]:
    """Return the model modules the engine fixture imports into ``TenantBase``."""
    return ("jdlib.models.org", "jdlib.models.settings", "jdlib.models.audit")


@pytest.fixture(scope="session")
def jdlib_database_url() -> str:
    """Return ``JDLIB_TEST_DATABASE_URL``, skipping the requesting test when unset."""
    url = os.environ.get("JDLIB_TEST_DATABASE_URL")
    if not url:
        pytest.skip(
            "jdlib database tests need JDLIB_TEST_DATABASE_URL "
            "(or a conftest override of the jdlib_database_url fixture)"
        )
    return url


@pytest.fixture(scope="session")
def jdlib_schema() -> str:
    """Return ``JDLIB_TEST_SCHEMA``, defaulting to ``jdlib_test``."""
    return os.environ.get("JDLIB_TEST_SCHEMA", "jdlib_test")


@pytest.fixture()
def jdlib_models() -> tuple[str, ...]:
    """Return the model modules to import; override in conftest to extend."""
    return jdlib_test_models()


if pytest_asyncio is None:

    @pytest.fixture()
    def jdlib_engine() -> None:
        """Skip async database fixtures when ``pytest-asyncio`` is not installed."""
        pytest.skip("install pytest-asyncio to use jdlib fixtures")

else:

    @pytest_asyncio.fixture()
    async def jdlib_engine(
        jdlib_database_url: str, jdlib_schema: str, jdlib_models: tuple[str, ...]
    ) -> AsyncIterator[AsyncEngine]:
        """Yield an async engine with the tenant schema and ``TenantBase`` tables created."""
        for module_name in jdlib_models:
            importlib.import_module(module_name)
        engine = create_async_engine(
            _async_dsn(jdlib_database_url),
            connect_args={"server_settings": {"search_path": f"{jdlib_schema}, public"}},
        )
        try:
            async with engine.begin() as connection:
                quoted = connection.dialect.identifier_preparer.quote(jdlib_schema)
                await connection.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {quoted}"))
                await connection.run_sync(TenantBase.metadata.create_all)
            yield engine
        finally:
            await engine.dispose()


@pytest.fixture()
def jdlib_session_factory(jdlib_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Return a session factory bound to ``jdlib_engine`` with ``expire_on_commit=False``."""
    return async_sessionmaker(jdlib_engine, expire_on_commit=False)


def _async_dsn(url: str) -> str:
    for prefix in ("postgresql+psycopg://", "postgresql+psycopg2://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+asyncpg://" + url[len(prefix) :]
    return url
