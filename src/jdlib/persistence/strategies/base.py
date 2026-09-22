from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import TenantRecord
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.strategies.deprovision import DeprovisionMode


@dataclass(frozen=True, slots=True)
class StrategyCapabilities:
    supports_rls: bool
    supports_ddl: bool


class IsolationStrategy(Protocol):
    name: str
    capabilities: StrategyCapabilities

    async def session(self, tenant: TenantRecord) -> AsyncSession: ...

    async def provision(self, tenant: TenantRecord) -> None: ...

    async def migrate(self, tenant: TenantRecord, runner: MigrationRunner) -> None: ...

    def migration_schema(self, tenant: TenantRecord) -> str: ...

    async def deprovision(self, tenant: TenantRecord, mode: DeprovisionMode) -> None: ...
