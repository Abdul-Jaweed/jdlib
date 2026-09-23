from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from jdlib.config import RlsConfig
from jdlib.context import TenantRecord
from jdlib.errors import StrategyCapabilityError
from jdlib.migrations.runner import DEPLOYMENT_SCHEMA_RE, MigrationRunner
from jdlib.persistence.strategies.base import StrategyCapabilities
from jdlib.persistence.strategies.deprovision import DeprovisionMode


class SharedSchemaStrategy:
    name = "shared"
    capabilities = StrategyCapabilities(supports_rls=True, supports_ddl=False)

    def __init__(
        self,
        engine: AsyncEngine | None,
        schema: str = "public",
        *,
        rls: RlsConfig | None = None,
    ) -> None:
        if DEPLOYMENT_SCHEMA_RE.fullmatch(schema) is None:
            raise StrategyCapabilityError(f"invalid schema name: {schema!r}")
        self._engine = engine
        self._schema = schema
        self._rls = rls

    async def session(self, tenant: TenantRecord) -> AsyncSession:
        if self._engine is None:
            raise StrategyCapabilityError("shared strategy has no engine configured")
        session = AsyncSession(self._engine, expire_on_commit=False)
        if self._rls is not None and self._rls.enabled:
            tenant_id = str(tenant.id)

            def _bind_tenant(
                sync_session: sa.orm.Session, transaction: Any, connection: sa.Connection
            ) -> None:
                connection.execute(
                    sa.text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
                    {"tenant_id": tenant_id},
                )

            try:
                sa.event.listen(session.sync_session, "after_begin", _bind_tenant)
            except Exception:
                await session.close()
                raise
        return session

    async def provision(self, tenant: TenantRecord) -> None:
        return None

    async def migrate(self, tenant: TenantRecord, runner: MigrationRunner) -> None:
        runner.upgrade_tenant(self._schema)

    def migration_schema(self, tenant: TenantRecord) -> str:
        return self._schema

    async def deprovision(self, tenant: TenantRecord, mode: DeprovisionMode) -> None:
        return None
