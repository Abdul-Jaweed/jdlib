from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import PRIVILEGE_ISSUER, ContextFactory, TenantRecord
from jdlib.persistence.models import tenant_table_map
from jdlib.persistence.session import TenantSession


class TenantPlanePurger:
    def __init__(
        self, session_factory: Callable[[], AsyncSession], *, factory: ContextFactory
    ) -> None:
        self._session_factory = session_factory
        self._factory = factory

    async def purge(self, tenant: TenantRecord) -> dict[str, int]:
        context = await self._factory.for_system(
            tenant, purpose="tenant.purge", issuer=PRIVILEGE_ISSUER
        )
        counts: dict[str, int] = {}
        async with TenantSession(self._session_factory(), context) as session:
            for name, model in tenant_table_map().items():
                counts[name] = await session.delete_where(model)
            await session.commit()
        return counts
