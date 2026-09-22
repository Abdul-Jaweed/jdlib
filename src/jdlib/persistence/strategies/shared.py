from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from jdlib.context import TenantRecord
from jdlib.errors import StrategyCapabilityError
from jdlib.migrations.runner import DEPLOYMENT_SCHEMA_RE, MigrationRunner
from jdlib.persistence.strategies.base import StrategyCapabilities
from jdlib.persistence.strategies.deprovision import DeprovisionMode


class SharedSchemaStrategy:
    name = "shared"
    capabilities = StrategyCapabilities(supports_rls=True, supports_ddl=False)

    def __init__(self, engine: AsyncEngine | None, schema: str = "public") -> None:
        if DEPLOYMENT_SCHEMA_RE.fullmatch(schema) is None:
            raise StrategyCapabilityError(f"invalid schema name: {schema!r}")
        self._engine = engine
        self._schema = schema

    async def session(self, tenant: TenantRecord) -> AsyncSession:
        if self._engine is None:
            raise StrategyCapabilityError("shared strategy has no engine configured")
        return AsyncSession(self._engine, expire_on_commit=False)

    async def provision(self, tenant: TenantRecord) -> None:
        return None

    async def migrate(self, tenant: TenantRecord, runner: MigrationRunner) -> None:
        runner.upgrade_tenant(self._schema)

    def migration_schema(self, tenant: TenantRecord) -> str:
        return self._schema

    async def deprovision(self, tenant: TenantRecord, mode: DeprovisionMode) -> None:
        return None
