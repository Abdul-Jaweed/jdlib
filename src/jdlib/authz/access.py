from __future__ import annotations

import uuid
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any, Protocol, cast

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import AccessReader
from jdlib.authz.resource_types import ResourceTypeRegistry
from jdlib.context import Principal, TenantContext
from jdlib.control.audit import PlatformAudit
from jdlib.control.enums import ScopeType
from jdlib.control.models import (
    Invitation,
    Membership,
    ResourceGrant,
    Role,
    RoleBinding,
    RolePermission,
    ServiceAccount,
)
from jdlib.control.session import ControlPlaneSession
from jdlib.errors import (
    AuthorizationError,
    CrossTenantReferenceError,
    InvalidReference,
    InvalidResourcePermission,
    RoleEscalationBlocked,
    RoleScopeMismatch,
)
from jdlib.models.org import Team


@dataclass(frozen=True, slots=True)
class ScopeRecord:
    """Ownership facts about an org/team scope row (tenant plane)."""

    tenant_id: uuid.UUID
    deleted: bool = False


class ScopeLookup(Protocol):
    """Resolves an org/team scope id to its owning tenant.

    Returns ``None`` when no row with the given id exists anywhere;
    otherwise the owning tenant and whether the row is soft-deleted.
    """

    async def __call__(
        self, tenant_id: uuid.UUID, scope_type: str, scope_id: uuid.UUID
    ) -> ScopeRecord | None: ...


class TenantWriteSession(Protocol):
    """The tenant-plane session surface ownership changes require.

    ``TenantSession`` satisfies this structurally; AccessControl never opens
    the tenant plane itself.
    """

    context: TenantContext

    async def execute(self, statement: sa.Executable) -> sa.Result[Any]: ...

    async def flush(self) -> None: ...


class AccessControl:
    def __init__(
        self,
        *,
        session_factory: Callable[[], AsyncSession],
        catalog: PermissionCatalog,
        reader: AccessReader,
        cache: AuthzCache,
        audit: PlatformAudit,
        registry: ResourceTypeRegistry | None = None,
        scope_lookup: ScopeLookup | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._catalog = catalog
        self._catalog_codes = frozenset(permission.code for permission in catalog.all())
        self._reader = reader
        self._cache = cache
        self._audit = audit
        self._registry = registry or ResourceTypeRegistry()
        self._scope_lookup = scope_lookup

    async def _session(self) -> ControlPlaneSession:
        return ControlPlaneSession(self._session_factory())

    async def actor_permissions(self, tenant_id: uuid.UUID, principal: Principal) -> frozenset[str]:
        bindings = await self._reader.bindings_for(
            principal, tenant_id, {(ScopeType.TENANT, None)}
        )
        by_role = await self._reader.permissions_by_role(
            tenant_id, [binding.role_id for binding in bindings]
        )
        held = frozenset().union(*by_role.values()) if by_role else frozenset()
        if principal.scopes is not None:
            return held & principal.scopes
        return held

    async def _require_subset(
        self, tenant_id: uuid.UUID, permissions: Collection[str], principal: Principal
    ) -> None:
        held = await self.actor_permissions(tenant_id, principal)
        missing = set(permissions) - held
        if missing:
            raise RoleEscalationBlocked(f"missing permissions: {sorted(missing)}")

    async def _require_permission(
        self, tenant_id: uuid.UUID, permission: str, principal: Principal
    ) -> frozenset[str]:
        held = await self.actor_permissions(tenant_id, principal)
        if permission not in held:
            raise AuthorizationError(f"missing permission: {permission}")
        return held

    def _validate_codes(self, permissions: Collection[str]) -> None:
        for code in permissions:
            self._catalog.validate(code)

    async def _validate_scope(
        self, tenant_id: uuid.UUID, scope_type: str, scope_id: uuid.UUID
    ) -> None:
        if self._scope_lookup is None:
            raise AuthorizationError(f"{scope_type} scope validation is not configured")
        record = await self._scope_lookup(tenant_id, scope_type, scope_id)
        if record is None:
            raise InvalidReference(f"{scope_type} scope not found: {scope_id}")
        if record.tenant_id != tenant_id or record.deleted:
            raise CrossTenantReferenceError(
                f"{scope_type} scope {scope_id}", str(tenant_id), str(record.tenant_id)
            )

    async def _lock(self, session: ControlPlaneSession, tenant_id: uuid.UUID) -> None:
        await session.execute(
            sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))").bindparams(
                key=f"jdlib:tenant:{tenant_id}"
            )
        )

    async def create_role(
        self,
        tenant_id: uuid.UUID,
        name: str,
        permissions: Collection[str],
        *,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
        is_system: bool = False,
    ) -> Role:
        await self._require_permission(tenant_id, "role:manage", actor_principal)
        self._validate_codes(permissions)
        await self._require_subset(tenant_id, permissions, actor_principal)
        self._cache.invalidate()
        async with await self._session() as session:
            existing = (
                await session.execute(
                    sa.select(Role).where(Role.tenant_id == tenant_id, Role.name == name)
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise AuthorizationError(f"role already exists: {name}")
            role = Role(tenant_id=tenant_id, name=name, is_system=is_system)
            session.add(role)
            await session.flush()
            for code in permissions:
                session.add(
                    RolePermission(tenant_id=tenant_id, role_id=role.id, permission_code=code)
                )
            await self._audit.record(
                action="role.created",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"role_id": str(role.id), "name": name},
            )
            await session.commit()
            return role

    async def update_role(
        self,
        tenant_id: uuid.UUID,
        role_id: uuid.UUID,
        permissions: Collection[str],
        *,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> Role:
        await self._require_permission(tenant_id, "role:manage", actor_principal)
        self._validate_codes(permissions)
        await self._require_subset(tenant_id, permissions, actor_principal)
        self._cache.invalidate()
        async with await self._session() as session:
            role: Role | None = await session.get(Role, {"tenant_id": tenant_id, "id": role_id})
            if role is None:
                raise InvalidReference(f"role not found: {role_id}")
            if role.is_system:
                raise AuthorizationError("system roles are immutable")
            existing_codes = set(
                (
                    await session.execute(
                        sa.select(RolePermission.permission_code).where(
                            RolePermission.tenant_id == tenant_id,
                            RolePermission.role_id == role_id,
                        )
                    )
                )
                .scalars()
                .all()
            )
            await session.execute(
                sa.delete(RolePermission).where(
                    RolePermission.tenant_id == tenant_id, RolePermission.role_id == role_id
                )
            )
            for code in permissions:
                session.add(
                    RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code=code)
                )
            new_codes = set(permissions)
            await self._audit.record(
                action="role.permissions_changed",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={
                    "role_id": str(role_id),
                    "permissions": sorted(new_codes),
                    "added": sorted(new_codes - existing_codes),
                    "removed": sorted(existing_codes - new_codes),
                },
            )
            await session.commit()
            return role

    async def delete_role(
        self,
        tenant_id: uuid.UUID,
        role_id: uuid.UUID,
        *,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> None:
        await self._require_permission(tenant_id, "role:manage", actor_principal)
        self._cache.invalidate()
        async with await self._session() as session:
            role = await session.get(Role, {"tenant_id": tenant_id, "id": role_id})
            if role is None:
                raise InvalidReference(f"role not found: {role_id}")
            if role.is_system:
                raise AuthorizationError("system roles are immutable")
            bindings = (
                await session.execute(
                    sa.select(sa.func.count()).select_from(RoleBinding).where(
                        RoleBinding.tenant_id == tenant_id, RoleBinding.role_id == role_id
                    )
                )
            ).scalar_one()
            invitations = (
                await session.execute(
                    sa.select(sa.func.count()).select_from(Invitation).where(
                        Invitation.tenant_id == tenant_id,
                        Invitation.role_id == role_id,
                    )
                )
            ).scalar_one()
            if bindings or invitations:
                raise AuthorizationError("role has bindings or invitations")
            await session.execute(
                sa.delete(RolePermission).where(
                    RolePermission.tenant_id == tenant_id, RolePermission.role_id == role_id
                )
            )
            await session.delete(role)
            await self._audit.record(
                action="role.deleted",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"role_id": str(role_id)},
            )
            await session.commit()

    async def bind_role(
        self,
        tenant_id: uuid.UUID,
        role_id: uuid.UUID,
        *,
        principal_type: str,
        principal_id: uuid.UUID,
        scope_type: str,
        scope_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> RoleBinding:
        held = await self._require_permission(tenant_id, "role:manage", actor_principal)
        try:
            scope = ScopeType(scope_type)
        except ValueError as exc:
            raise InvalidReference(f"unsupported scope type: {scope_type}") from exc
        if scope is ScopeType.TENANT:
            if scope_id is not None:
                raise InvalidReference("tenant scope must not carry a scope id")
        elif scope_id is None:
            raise InvalidReference(f"{scope_type} scope requires a scope id")
        else:
            await self._validate_scope(tenant_id, scope.value, scope_id)
        async with await self._session() as session:
            role = await session.get(Role, {"tenant_id": tenant_id, "id": role_id})
            if role is None:
                raise InvalidReference(f"role not found: {role_id}")
            if role.name == "owner" and not self._catalog_codes <= held:
                raise AuthorizationError("only a full-catalog actor may assign the owner role")
            codes = (
                await session.execute(
                    sa.select(RolePermission.permission_code).where(
                        RolePermission.tenant_id == tenant_id, RolePermission.role_id == role_id
                    )
                )
            ).scalars().all()
            for code in codes:
                permission = self._catalog.validate(code)
                if scope not in permission.allowed_scopes:
                    raise RoleScopeMismatch(f"{code} cannot be bound at {scope_type} scope")
            await self._validate_principal(session, tenant_id, principal_type, principal_id)
        await self._require_subset(tenant_id, codes, actor_principal)
        self._cache.invalidate()
        async with await self._session() as session:
            binding = RoleBinding(
                tenant_id=tenant_id,
                role_id=role_id,
                principal_type=principal_type,
                principal_id=principal_id,
                scope_type=scope_type,
                scope_id=scope_id,
                created_by=actor_id,
            )
            session.add(binding)
            await self._audit.record(
                action="binding.created",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={
                    "role_id": str(role_id),
                    "principal_id": str(principal_id),
                    "scope": f"{scope_type}:{scope_id}",
                },
            )
            await session.commit()
            return binding

    async def _validate_principal(
        self,
        session: ControlPlaneSession,
        tenant_id: uuid.UUID,
        principal_type: str,
        principal_id: uuid.UUID,
    ) -> None:
        if principal_type == "service_account":
            account = await session.get(
                ServiceAccount, {"tenant_id": tenant_id, "id": principal_id}
            )
            if account is None or account.status != "active":
                raise CrossTenantReferenceError(
                    "service_account", str(tenant_id), str(principal_id)
                )
            return
        membership = (
            await session.execute(
                sa.select(Membership).where(
                    Membership.tenant_id == tenant_id,
                    Membership.user_id == principal_id,
                    Membership.status == "active",
                )
            )
        ).scalar_one_or_none()
        if membership is None:
            raise CrossTenantReferenceError("membership", str(tenant_id), str(principal_id))

    async def unbind_role(
        self,
        tenant_id: uuid.UUID,
        binding_id: uuid.UUID,
        *,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> None:
        await self._require_permission(tenant_id, "role:manage", actor_principal)
        self._cache.invalidate()
        async with await self._session() as session:
            await self._lock(session, tenant_id)
            binding = await session.get(
                RoleBinding, {"tenant_id": tenant_id, "id": binding_id}
            )
            if binding is None:
                raise InvalidReference(f"binding not found: {binding_id}")
            role = await session.get(Role, {"tenant_id": tenant_id, "id": binding.role_id})
            if role is not None and role.name == "owner":
                remaining = (
                    await session.execute(
                        sa.select(sa.func.count())
                        .select_from(RoleBinding)
                        .join(
                            Role,
                            sa.and_(
                                Role.tenant_id == RoleBinding.tenant_id,
                                Role.id == RoleBinding.role_id,
                            ),
                        )
                        .where(
                            RoleBinding.tenant_id == tenant_id,
                            Role.name == "owner",
                            RoleBinding.id != binding_id,
                        )
                    )
                ).scalar_one()
                if remaining == 0:
                    raise AuthorizationError("cannot remove the last owner")
            await session.delete(binding)
            await self._audit.record(
                action="binding.removed",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"binding_id": str(binding_id)},
            )
            await session.commit()

    async def grant_resource(
        self,
        tenant_id: uuid.UUID,
        *,
        resource_type: str,
        resource_id: uuid.UUID,
        principal_type: str,
        principal_id: uuid.UUID,
        permission: str,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> ResourceGrant:
        definition = self._registry.get(resource_type)
        if self._catalog.validate(permission).namespace != definition.permission_namespace:
            raise InvalidResourcePermission(
                f"{permission} is not valid for resource type {resource_type}"
            )
        await self._require_subset(tenant_id, [permission, "resource:share"], actor_principal)
        self._cache.invalidate()
        async with await self._session() as session:
            existing: ResourceGrant | None = (
                await session.execute(
                    sa.select(ResourceGrant).where(
                        ResourceGrant.tenant_id == tenant_id,
                        ResourceGrant.resource_type == resource_type,
                        ResourceGrant.resource_id == resource_id,
                        ResourceGrant.principal_type == principal_type,
                        ResourceGrant.principal_id == principal_id,
                        ResourceGrant.permission_code == permission,
                    )
                )
            ).scalar_one_or_none()
            if existing is not None:
                return existing
            grant = ResourceGrant(
                tenant_id=tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                principal_type=principal_type,
                principal_id=principal_id,
                permission_code=permission,
                created_by=actor_id,
            )
            session.add(grant)
            await self._audit.record(
                action="grant.created",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={
                    "resource": f"{resource_type}:{resource_id}",
                    "permission": permission,
                    "principal_id": str(principal_id),
                },
            )
            await session.commit()
            return grant

    async def revoke_grant(
        self,
        tenant_id: uuid.UUID,
        grant_id: uuid.UUID,
        *,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
    ) -> None:
        self._cache.invalidate()
        async with await self._session() as session:
            grant = await session.get(ResourceGrant, {"tenant_id": tenant_id, "id": grant_id})
            if grant is None:
                raise InvalidReference(f"grant not found: {grant_id}")
            await session.delete(grant)
            await self._audit.record(
                action="grant.revoked",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"grant_id": str(grant_id)},
            )
            await session.commit()

    async def transfer_resource(
        self,
        session: TenantWriteSession,
        *,
        resource_type: str,
        resource_id: uuid.UUID,
        to_organization_id: uuid.UUID | None,
        to_team_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
        revoke_grants: bool = False,
    ) -> None:
        definition = self._registry.get(resource_type)
        model = cast(Any, definition.model)
        context = getattr(session, "context", None)
        if context is None:
            raise InvalidReference("transfer requires a tenant session")
        if to_team_id is not None and to_organization_id is None:
            raise InvalidReference("team ownership requires an organization")
        self._cache.invalidate()
        row = (
            await session.execute(sa.select(model).where(model.id == resource_id))
        ).scalar_one_or_none()
        if row is None:
            raise InvalidReference(f"resource not found: {resource_id}")
        previous = (row.organization_id, row.team_id)
        row.organization_id = to_organization_id
        row.team_id = to_team_id
        if revoke_grants:
            await session.execute(
                sa.delete(ResourceGrant).where(
                    ResourceGrant.tenant_id == context.tenant_id,
                    ResourceGrant.resource_type == resource_type,
                    ResourceGrant.resource_id == resource_id,
                )
            )
        await session.flush()
        await self._audit.record(
            action="resource.owner_changed",
            tenant_id=context.tenant_id,
            actor_id=actor_id,
            metadata={
                "resource": f"{resource_type}:{resource_id}",
                "from": f"{previous[0]}:{previous[1]}",
                "to": f"{to_organization_id}:{to_team_id}",
            },
        )

    async def move_team(
        self,
        session: TenantWriteSession,
        *,
        team_id: uuid.UUID,
        to_organization_id: uuid.UUID,
        actor_id: uuid.UUID | None,
        actor_principal: Principal,
        revoke_grants: bool = False,
    ) -> None:
        context = getattr(session, "context", None)
        if context is None:
            raise InvalidReference("team move requires a tenant session")
        self._cache.invalidate()
        team = (
            await session.execute(sa.select(Team).where(Team.id == team_id))
        ).scalar_one_or_none()
        if team is None:
            raise InvalidReference(f"team not found: {team_id}")
        previous = team.organization_id
        team.organization_id = to_organization_id
        if revoke_grants:
            await self._revoke_team_grants(session, context.tenant_id, team_id)
        await session.flush()
        await self._audit.record(
            action="team.moved",
            tenant_id=context.tenant_id,
            actor_id=actor_id,
            metadata={
                "team": str(team_id),
                "from": str(previous),
                "to": str(to_organization_id),
            },
        )

    async def _revoke_team_grants(
        self, session: TenantWriteSession, tenant_id: uuid.UUID, team_id: uuid.UUID
    ) -> None:
        for definition in self._registry.all():
            model = cast(Any, definition.model)
            if not hasattr(model, "team_id"):
                continue
            resource_ids = (
                await session.execute(sa.select(model.id).where(model.team_id == team_id))
            ).scalars().all()
            if not resource_ids:
                continue
            await session.execute(
                sa.delete(ResourceGrant).where(
                    ResourceGrant.tenant_id == tenant_id,
                    ResourceGrant.resource_type == definition.resource_type,
                    ResourceGrant.resource_id.in_(resource_ids),
                )
            )
