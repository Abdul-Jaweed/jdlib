"""Response models. What leaves the process is declared here, not assembled ad hoc.

None of these carries an internal identifier a caller has no use for: a response is the tenant's
own data and the ids it needs to correlate its request, and nothing else.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, Field

from examples.enterprise.app.models.resources import Entity, Resource


class WhoAmI(BaseModel):
    """The caller's own view of the request: who, in which tenant, under which request."""

    tenant: str
    principal_kind: str
    principal_id: str
    scopes: list[str]
    request_id: str
    correlation_id: str


class TenantSummary(BaseModel):
    """The tenant this request is scoped to."""

    slug: str
    strategy: str


class ResourceCreate(BaseModel):
    """What a caller may send when creating a resource."""

    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(default="document", pattern="^(document|dataset|model)$")


class ResourceOut(BaseModel):
    """One resource, as the tenant sees it."""

    id: str
    name: str
    kind: str
    status: str
    created_at: str

    @classmethod
    def of(cls, resource: Resource) -> ResourceOut:
        return cls(
            id=str(resource.id),
            name=resource.name,
            kind=resource.kind,
            status=resource.status,
            created_at=resource.created_at.isoformat(),
        )


class ResourcePage(BaseModel):
    """A page of resources, with the window it was read through."""

    resources: list[ResourceOut]
    limit: int
    offset: int

    @classmethod
    def of(cls, rows: Sequence[Resource], *, limit: int, offset: int) -> ResourcePage:
        return cls(
            resources=[ResourceOut.of(row) for row in rows], limit=limit, offset=offset
        )


class EntityCreate(BaseModel):
    """What a caller may send when attaching an entity."""

    label: str = Field(min_length=1, max_length=200)
    weight: int = Field(default=1, ge=0, le=1000)


class EntityOut(BaseModel):
    """One entity, as the tenant sees it."""

    id: str
    resource_id: str
    label: str
    weight: int

    @classmethod
    def of(cls, entity: Entity) -> EntityOut:
        return cls(
            id=str(entity.id),
            resource_id=str(entity.resource_id),
            label=entity.label,
            weight=entity.weight,
        )


__all__ = [
    "EntityCreate",
    "EntityOut",
    "ResourceCreate",
    "ResourceOut",
    "ResourcePage",
    "TenantSummary",
    "WhoAmI",
]
