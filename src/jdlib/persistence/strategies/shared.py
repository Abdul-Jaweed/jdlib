from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from jdlib.context import TenantRecord
from jdlib.persistence.strategies.base import StrategyCapabilities


class SharedSchemaStrategy:
    name = "shared"
    capabilities = StrategyCapabilities(supports_rls=True, supports_ddl=False)

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def session(self, tenant: TenantRecord) -> AsyncSession:
        return AsyncSession(self._engine, expire_on_commit=False)
