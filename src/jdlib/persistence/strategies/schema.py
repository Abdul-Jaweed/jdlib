from __future__ import annotations

import re
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.pool import PoolResetState

from jdlib.context import TenantRecord
from jdlib.errors import StrategyCapabilityError
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.strategies.base import StrategyCapabilities
from jdlib.persistence.strategies.deprovision import DeprovisionMode

_SCHEMA_RE = re.compile(r"^t_[a-z0-9][a-z0-9_]{0,50}$")


def validate_schema_name(value: str) -> str:
    if not _SCHEMA_RE.fullmatch(value):
        raise StrategyCapabilityError(f"invalid tenant schema name: {value!r}")
    return value


def _handle(tenant: TenantRecord) -> str:
    if tenant.target_handle is None:
        raise StrategyCapabilityError(f"tenant {tenant.slug} has no schema handle")
    return validate_schema_name(tenant.target_handle)


def _reset_search_path(
    dbapi_connection: Any, connection_record: Any, reset_state: PoolResetState
) -> None:
    if not reset_state.asyncio_safe or reset_state.terminate_only:
        return
    dbapi_connection.rollback()
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("RESET search_path")
    finally:
        cursor.close()
    dbapi_connection.commit()


class SchemaPerTenantStrategy:
    name = "schema"
    capabilities = StrategyCapabilities(supports_rls=False, supports_ddl=True)

    def __init__(
        self,
        engine: AsyncEngine | None,
        runner: MigrationRunner | None = None,
        *,
        admin_engine: AsyncEngine | None = None,
    ) -> None:
        self._engine = engine
        self._runner = runner
        self._admin_engine = admin_engine
        if engine is not None:
            sync_engine = engine.sync_engine
            if not sa.event.contains(sync_engine, "reset", _reset_search_path):
                sa.event.listen(sync_engine, "reset", _reset_search_path, retval=False)

    def migration_schema(self, tenant: TenantRecord) -> str:
        return _handle(tenant)

    async def session(self, tenant: TenantRecord) -> AsyncSession:
        schema = _handle(tenant)
        if self._engine is None:
            raise StrategyCapabilityError("schema strategy has no engine configured")
        quoted = self._engine.dialect.identifier_preparer.quote(schema)
        session = AsyncSession(self._engine, expire_on_commit=False)

        def _set_search_path(
            sync_session: sa.orm.Session, transaction: Any, connection: sa.Connection
        ) -> None:
            connection.exec_driver_sql(f"SET search_path TO {quoted}")

        try:
            sa.event.listen(session.sync_session, "after_begin", _set_search_path)
        except Exception:
            await session.close()
            raise
        return session

    async def provision(self, tenant: TenantRecord) -> None:
        schema = _handle(tenant)
        engine = self._admin_engine or self._engine
        if engine is None:
            raise StrategyCapabilityError("schema strategy has no engine configured")
        async with engine.begin() as connection:
            quoted = connection.dialect.identifier_preparer.quote(schema)
            await connection.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {quoted}"))

    async def migrate(self, tenant: TenantRecord, runner: MigrationRunner) -> None:
        runner.upgrade_tenant(self.migration_schema(tenant))

    async def deprovision(self, tenant: TenantRecord, mode: DeprovisionMode) -> None:
        if mode is DeprovisionMode.ARCHIVE:
            return
        schema = _handle(tenant)
        engine = self._admin_engine or self._engine
        if engine is None:
            raise StrategyCapabilityError("schema strategy has no engine configured")
        async with engine.begin() as connection:
            quoted = connection.dialect.identifier_preparer.quote(schema)
            await connection.execute(sa.text(f"DROP SCHEMA IF EXISTS {quoted} CASCADE"))
