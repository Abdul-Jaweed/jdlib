from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import TenantRecord


@dataclass(frozen=True, slots=True)
class StrategyCapabilities:
    supports_rls: bool
    supports_ddl: bool


class IsolationStrategy(Protocol):
    name: str
    capabilities: StrategyCapabilities

    async def session(self, tenant: TenantRecord) -> AsyncSession: ...
