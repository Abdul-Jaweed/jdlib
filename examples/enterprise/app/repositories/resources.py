"""Repositories for the tenant plane's two tables.

`TenantRepository` supplies the operations and applies the live-row criteria (`deleted_at IS NULL`)
on every read; these subclasses add the reads the API needs and nothing else.

What they deliberately do **not** have is a method taking a tenant id. The tenant is not a
parameter anywhere in this layer: it comes from the session, which was bound to one tenant at
connect time, and from the library's own scoping hooks. A repository method with a `tenant_id`
argument would be the first place that rule could be forgotten, and every caller after it would
inherit the habit.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from examples.enterprise.app.models.resources import Entity, Resource
from jdlib.persistence.repository import TenantRepository
from jdlib.persistence.session import TenantSession

__all__ = ["EntityRepository", "ResourceRepository"]


class ResourceRepository(TenantRepository[Resource]):
    def __init__(self, session: TenantSession) -> None:
        super().__init__(session, Resource)

    async def by_name(self, name: str) -> Resource | None:
        """The live resource with this name in the session's tenant, if there is one."""
        rows = await self.list(Resource.name == name, limit=1)
        return rows[0] if rows else None

    async def page(self, *, limit: int, offset: int = 0) -> Sequence[Resource]:
        return await self.list(order_by=sa.desc(Resource.created_at), limit=limit, offset=offset)


class EntityRepository(TenantRepository[Entity]):
    def __init__(self, session: TenantSession) -> None:
        super().__init__(session, Entity)

    async def for_resource(self, resource_id: object) -> Sequence[Entity]:
        return await self.list(Entity.resource_id == resource_id, order_by=sa.desc(Entity.label))
