from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, cast

import sqlalchemy as sa

from jdlib.authz.resource_types import ResourceTypeRegistry
from jdlib.control.enums import ScopeType
from jdlib.models.org import Organization, Team
from jdlib.persistence.session import TenantSession


@dataclass(frozen=True, slots=True)
class ScopeRef:
    type: ScopeType
    id: uuid.UUID | None


@dataclass(frozen=True, slots=True)
class ResourceRef:
    resource_type: str
    resource_id: uuid.UUID


Target = ScopeRef | ResourceRef


class ScopeResolver:
    def __init__(self, registry: ResourceTypeRegistry) -> None:
        self._registry = registry

    async def chain(self, session: TenantSession, target: Target) -> tuple[ScopeRef, ...]:
        tenant = ScopeRef(ScopeType.TENANT, None)
        if isinstance(target, ScopeRef):
            if target.type is ScopeType.TENANT:
                return (tenant,)
            if target.id is None:
                raise ValueError(f"{target.type} scope requires a scope id")
            if target.type is ScopeType.ORG:
                return (tenant, *await self._org_chain(session, target.id))
            if target.type is ScopeType.TEAM:
                team = await session.get(Team, target.id)
                if team is None:
                    return (tenant,)
                return (
                    tenant,
                    *await self._org_chain(session, team.organization_id),
                    ScopeRef(ScopeType.TEAM, target.id),
                )
            raise ValueError(f"unsupported scope type: {target.type}")
        definition = self._registry.get(target.resource_type)
        model = cast(Any, definition.model)
        row = (
            await session.execute(
                sa.select(model.organization_id, model.team_id).where(
                    model.id == target.resource_id
                )
            )
        ).first()
        if row is None:
            return (tenant,)
        organization_id, team_id = tuple(row)
        chain: list[ScopeRef] = [tenant]
        if organization_id is not None:
            chain.extend(await self._org_chain(session, organization_id))
        if team_id is not None:
            chain.append(ScopeRef(ScopeType.TEAM, team_id))
        return tuple(chain)

    async def _org_chain(self, session: TenantSession, org_id: uuid.UUID) -> list[ScopeRef]:
        chain: list[ScopeRef] = []
        seen: set[uuid.UUID] = set()
        current: uuid.UUID | None = org_id
        while current is not None and current not in seen:
            seen.add(current)
            organization = await session.get(Organization, current)
            if organization is None:
                break
            chain.append(ScopeRef(ScopeType.ORG, organization.id))
            current = organization.parent_organization_id
        return chain
