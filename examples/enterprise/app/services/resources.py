"""The resource service: one unit of work per operation, and the library's session underneath it.

Every method here opens a `UnitOfWork`, which is where three library controls live:

* the **write fence** (`RegistryWriteFence`) refuses a write to a tenant that is not writable —
  suspended, archived, relocating — before a connection is even taken;
* the **tenant binding** comes from the session factory, so no method below names a tenant;
* the **commit boundary** is the `async with`: a clean exit commits, an exception rolls back, and
  nothing is left half-applied.

The service does not catch the library's refusals (`UnscopedRawSql`, `CrossTenantReferenceError`,
`TenantNotWritable`): they are the answer to "may this happen", and translating them into something
friendlier at this layer is how a refusal becomes a log line nobody reads. The API layer maps them
to status codes instead.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from examples.enterprise.app.dataplane import TenantPlane
from examples.enterprise.app.models.resources import Entity, Resource
from examples.enterprise.app.repositories.resources import EntityRepository, ResourceRepository
from jdlib.context import TenantContext
from jdlib.errors import InvalidReference
from jdlib.persistence.models import WriteFence
from jdlib.persistence.uow import UnitOfWork

__all__ = ["ResourceService"]


@dataclass(frozen=True)
class ResourceService:
    """The tenant plane's operations, each one a unit of work."""

    plane: TenantPlane
    fence: WriteFence

    def unit_of_work(self, context: TenantContext) -> UnitOfWork:
        return UnitOfWork(self.plane.session_factory_for(context), context, fence=self.fence)

    async def create(
        self, context: TenantContext, *, name: str, kind: str = "document"
    ) -> Resource:
        async with self.unit_of_work(context) as session:
            resource = Resource(
                tenant_id=context.tenant_id,
                id=uuid.uuid4(),
                name=name,
                kind=kind,
                status="active",
                created_by=context.principal.id,
            )
            return await ResourceRepository(session).add(resource)

    async def list(
        self, context: TenantContext, *, limit: int = 50, offset: int = 0
    ) -> Sequence[Resource]:
        async with self.unit_of_work(context) as session:
            return await ResourceRepository(session).page(limit=limit, offset=offset)

    async def get(self, context: TenantContext, resource_id: uuid.UUID) -> Resource | None:
        async with self.unit_of_work(context) as session:
            return await ResourceRepository(session).get(resource_id)

    async def require(self, context: TenantContext, resource_id: uuid.UUID) -> Resource:
        """The resource, or a refusal naming what was asked for."""
        resource = await self.get(context, resource_id)
        if resource is None:
            raise InvalidReference(f"resource {resource_id} does not exist in this tenant")
        return resource

    async def archive(self, context: TenantContext, resource_id: uuid.UUID) -> Resource:
        async with self.unit_of_work(context) as session:
            repository = ResourceRepository(session)
            resource = await repository.get(resource_id)
            if resource is None:
                raise InvalidReference(f"resource {resource_id} does not exist in this tenant")
            return await repository.update(resource, status="archived")

    async def add_entity(
        self,
        context: TenantContext,
        *,
        resource_id: uuid.UUID,
        label: str,
        weight: int = 1,
    ) -> Entity:
        """Attach an entity to a resource of this tenant.

        The reference is composite and tenant-first, so naming another tenant's resource is refused
        by the database's own constraint — the session's check reports it first, and the constraint
        is what remains true if the session is ever bypassed.
        """
        async with self.unit_of_work(context) as session:
            if await ResourceRepository(session).get(resource_id) is None:
                raise InvalidReference(f"resource {resource_id} does not exist in this tenant")
            entity = Entity(
                tenant_id=context.tenant_id,
                id=uuid.uuid4(),
                resource_id=resource_id,
                label=label,
                weight=weight,
            )
            return await EntityRepository(session).add(entity)

    async def entities(self, context: TenantContext, resource_id: uuid.UUID) -> Sequence[Entity]:
        async with self.unit_of_work(context) as session:
            return await EntityRepository(session).for_resource(resource_id)

    async def count(self, context: TenantContext) -> int:
        async with self.unit_of_work(context) as session:
            return await ResourceRepository(session).count()
