from __future__ import annotations

from collections.abc import Mapping

from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import TenantRecord
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import StrategyCapabilityError
from jdlib.persistence.strategies.base import IsolationStrategy


class SessionRouter:
    def __init__(self, strategies: Mapping[PlacementStrategy, IsolationStrategy]) -> None:
        self._strategies = dict(strategies)

    async def session(self, tenant: TenantRecord) -> AsyncSession:
        strategy = self._strategies.get(tenant.strategy)
        if strategy is None:
            raise StrategyCapabilityError(
                f"no isolation strategy registered for {tenant.strategy}"
            )
        return await strategy.session(tenant)
