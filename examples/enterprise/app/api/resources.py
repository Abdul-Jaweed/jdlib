"""The resource routes: one unit of work per request, and a declared permission on each.

Each route declares what it needs (`require("resource:read")`, `require("resource:write")`) and the
handler then does one thing: call the service. There is no tenant id in any signature and no query
in this file — the session the service opens is already bound to the tenant, and the policies in
`config/cerbos/policies/` are written against the same permission strings.

Failures are not caught here. `InvalidReference`, `CrossTenantReferenceError`, `TenantNotWritable`,
`UnscopedRawSql` and a duplicate name's `IntegrityError` all have answers in the library's envelope
table, and re-mapping them at this layer is how an application grows a second, quietly different
error contract.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.exc import IntegrityError

from examples.enterprise.app.api.schemas import (
    EntityCreate,
    EntityOut,
    ResourceCreate,
    ResourceOut,
    ResourcePage,
)
from examples.enterprise.app.services.resources import ResourceService
from jdlib.context import TenantContext
from jdlib.errors import InvalidReference
from jdlib.integrations.fastapi import get_context, require

__all__ = ["router"]

router = APIRouter(tags=["resources"])


def _service(request: Request) -> ResourceService:
    service: ResourceService = request.app.state.resources
    return service


ServiceDep = Annotated[ResourceService, Depends(_service)]
ContextDep = Annotated[TenantContext, Depends(get_context)]


@router.post(
    "/resources",
    status_code=201,
    dependencies=[Depends(require("resource:write"))],
    summary="Create a resource in the caller's tenant",
)
async def create_resource(
    payload: ResourceCreate, context: ContextDep, service: ServiceDep
) -> ResourceOut:
    try:
        resource = await service.create(context, name=payload.name, kind=payload.kind)
    except IntegrityError as error:
        # A duplicate name is the caller's to fix, and the unique index is what decided it.
        raise InvalidReference(
            f"a resource named {payload.name!r} already exists in this tenant"
        ) from error
    return ResourceOut.of(resource)


@router.get(
    "/resources",
    dependencies=[Depends(require("resource:read"))],
    summary="List the caller's tenant's resources",
)
async def list_resources(
    context: ContextDep, service: ServiceDep, limit: int = 50, offset: int = 0
) -> ResourcePage:
    rows = await service.list(context, limit=limit, offset=offset)
    return ResourcePage.of(rows, limit=limit, offset=offset)


@router.get(
    "/resources/{resource_id}",
    dependencies=[Depends(require("resource:read"))],
    summary="Read one resource",
)
async def get_resource(
    resource_id: uuid.UUID, context: ContextDep, service: ServiceDep
) -> ResourceOut:
    # Another tenant's resource is not "forbidden" here, it does not exist: the session is bound to
    # one tenant, so the row is unreachable rather than refused, and 404 is the honest answer.
    return ResourceOut.of(await service.require(context, resource_id))


@router.delete(
    "/resources/{resource_id}",
    dependencies=[Depends(require("resource:write"))],
    summary="Archive a resource (a soft delete)",
)
async def archive_resource(
    resource_id: uuid.UUID, context: ContextDep, service: ServiceDep
) -> ResourceOut:
    return ResourceOut.of(await service.archive(context, resource_id))


@router.post(
    "/resources/{resource_id}/entities",
    status_code=201,
    dependencies=[Depends(require("resource:write"))],
    summary="Attach an entity to one of the tenant's resources",
)
async def add_entity(
    resource_id: uuid.UUID, payload: EntityCreate, context: ContextDep, service: ServiceDep
) -> EntityOut:
    entity = await service.add_entity(
        context, resource_id=resource_id, label=payload.label, weight=payload.weight
    )
    return EntityOut.of(entity)


@router.get(
    "/resources/{resource_id}/entities",
    dependencies=[Depends(require("resource:read"))],
    summary="List a resource's entities",
)
async def list_entities(
    resource_id: uuid.UUID, context: ContextDep, service: ServiceDep
) -> list[EntityOut]:
    return [EntityOut.of(entity) for entity in await service.entities(context, resource_id)]
