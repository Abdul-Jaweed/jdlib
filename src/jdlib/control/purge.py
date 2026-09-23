from __future__ import annotations

from collections.abc import Callable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.config import RlsConfig
from jdlib.context import PRIVILEGE_ISSUER, ContextFactory, TenantRecord
from jdlib.models.base import TenantBase
from jdlib.persistence.models import tenant_table_map
from jdlib.persistence.session import TenantSession


def _delete_order() -> list[tuple[str, type]]:
    models = tenant_table_map()
    ordered: list[tuple[str, type]] = []
    seen: set[str] = set()
    for table in reversed(TenantBase.metadata.sorted_tables):
        model = models.get(table.name)
        if model is not None:
            ordered.append((table.name, model))
            seen.add(table.name)
    for name in sorted(models):
        if name not in seen:
            ordered.append((name, models[name]))
    return ordered


class TenantPlanePurger:
    def __init__(
        self,
        session_factory: Callable[[], AsyncSession],
        *,
        factory: ContextFactory,
        rls: RlsConfig | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._factory = factory
        self._rls = rls

    async def purge(self, tenant: TenantRecord) -> dict[str, int]:
        context = await self._factory.for_system(
            tenant, purpose="tenant.purge", issuer=PRIVILEGE_ISSUER
        )
        session = self._session_factory()
        try:
            if self._rls is not None and self._rls.enabled:
                await session.execute(
                    sa.text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
                    {"tenant_id": str(tenant.id)},
                )
        except Exception:
            await session.close()
            raise
        counts: dict[str, int] = {}
        async with TenantSession(session, context) as scoped:
            for name, model in _delete_order():
                counts[name] = await scoped.delete_where(model)
            await scoped.commit()
        return counts
