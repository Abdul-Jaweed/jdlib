from __future__ import annotations

import re
from collections import OrderedDict
from typing import cast

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import AsyncAdaptedQueuePool

from jdlib.context import TenantRecord
from jdlib.errors import PoolCapacityError, StrategyCapabilityError
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.secrets import SecretProvider
from jdlib.persistence.strategies.base import StrategyCapabilities
from jdlib.persistence.strategies.deprovision import DeprovisionMode

_HANDLE_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,50}")
_MIGRATION_SCHEMA = "public"


def _handle(tenant: TenantRecord) -> str:
    if tenant.target_handle is None or _HANDLE_RE.fullmatch(tenant.target_handle) is None:
        raise StrategyCapabilityError(f"invalid database handle for tenant {tenant.slug}")
    return tenant.target_handle


def _database_name(dsn: str) -> str:
    database = sa.engine.make_url(dsn).database
    if not database:
        raise StrategyCapabilityError("tenant database dsn has no database name")
    return database


class DatabasePerTenantStrategy:
    """Database-per-tenant isolation with a bounded, handle-keyed engine cache.

    Engines are created lazily from the secret resolved for each tenant handle
    and kept in LRU order. When ``max_targets`` is reached, eviction considers
    idle engines only, least-recently-used first; an engine with checked-out
    connections is never closed and cap pressure raises ``PoolCapacityError``.

    Secret rotation contract: a cached engine keeps the DSN that was resolved
    when it was created. Rotating a handle's secret takes effect only after
    that engine leaves the cache (deprovision, idle eviction, or ``dispose``);
    there is no hot reload.
    """

    name = "database"
    capabilities = StrategyCapabilities(supports_rls=False, supports_ddl=True)

    def __init__(
        self,
        *,
        admin_dsn: str,
        secrets: SecretProvider,
        runner: MigrationRunner | None = None,
        max_targets: int = 32,
    ) -> None:
        self._admin_dsn = admin_dsn
        self._secrets = secrets
        self._runner = runner
        self._max_targets = max_targets
        self._engines: OrderedDict[str, AsyncEngine] = OrderedDict()
        self._admin_engine: AsyncEngine | None = None

    def _resolve(self, tenant: TenantRecord) -> tuple[str, str]:
        handle = _handle(tenant)
        try:
            return handle, self._secrets.resolve(handle)
        except KeyError as exc:
            raise StrategyCapabilityError(
                f"no secret for database handle {handle}"
            ) from exc

    def migration_schema(self, tenant: TenantRecord) -> str:
        self._resolve(tenant)
        return _MIGRATION_SCHEMA

    async def _engine_for(self, tenant: TenantRecord) -> AsyncEngine:
        handle, dsn = self._resolve(tenant)
        engine = self._engines.get(handle)
        if engine is not None:
            self._engines.move_to_end(handle)
            return engine
        await self._evict_idle()
        if len(self._engines) >= self._max_targets:
            raise PoolCapacityError(f"database pool cap reached ({self._max_targets})")
        engine = create_async_engine(dsn)
        self._engines[handle] = engine
        return engine

    async def _evict_idle(self) -> None:
        while len(self._engines) >= self._max_targets:
            handle = next(
                (
                    name
                    for name, engine in self._engines.items()
                    if cast(AsyncAdaptedQueuePool, engine.pool).checkedout() == 0
                ),
                None,
            )
            if handle is None:
                return
            await self._engines.pop(handle).dispose()

    def _admin(self) -> AsyncEngine:
        if self._admin_engine is None:
            self._admin_engine = create_async_engine(self._admin_dsn)
        return self._admin_engine

    async def session(self, tenant: TenantRecord) -> AsyncSession:
        return AsyncSession(await self._engine_for(tenant), expire_on_commit=False)

    async def provision(self, tenant: TenantRecord) -> None:
        _, dsn = self._resolve(tenant)
        database = _database_name(dsn)
        quoted = self._admin().dialect.identifier_preparer.quote(database)
        async with self._admin().connect() as connection:
            auto = await connection.execution_options(isolation_level="AUTOCOMMIT")
            exists = (
                await auto.execute(
                    sa.text("SELECT 1 FROM pg_database WHERE datname = :name"),
                    {"name": database},
                )
            ).scalar_one_or_none()
            if exists is None:
                await auto.execute(sa.text(f"CREATE DATABASE {quoted}"))

    async def migrate(self, tenant: TenantRecord, runner: MigrationRunner) -> None:
        _, dsn = self._resolve(tenant)
        runner.upgrade_tenant_url(dsn, self.migration_schema(tenant))

    async def deprovision(self, tenant: TenantRecord, mode: DeprovisionMode) -> None:
        if mode is DeprovisionMode.ARCHIVE:
            return
        handle, dsn = self._resolve(tenant)
        database = _database_name(dsn)
        engine = self._engines.pop(handle, None)
        if engine is not None:
            await engine.dispose()
        quoted = self._admin().dialect.identifier_preparer.quote(database)
        async with self._admin().connect() as connection:
            auto = await connection.execution_options(isolation_level="AUTOCOMMIT")
            await auto.execute(
                sa.text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": database},
            )
            await auto.execute(sa.text(f"DROP DATABASE IF EXISTS {quoted}"))

    async def dispose(self) -> None:
        for engine in list(self._engines.values()):
            await engine.dispose()
        self._engines.clear()
        if self._admin_engine is not None:
            await self._admin_engine.dispose()
            self._admin_engine = None
