from __future__ import annotations

import secrets
import uuid
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

import sqlalchemy as sa
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib._uuid import uuid7
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


@dataclass(frozen=True, slots=True)
class ResourceRecord:
    """Ownership facts about a tenant-owned resource row (tenant plane)."""

    tenant_id: uuid.UUID
    deleted: bool = False


class ResourceLookup(Protocol):
    """Resolves a resource id to its owning tenant.

    Returns ``None`` when no row with the given id exists anywhere;
    otherwise the owning tenant and whether the row is soft-deleted.
    """

    async def __call__(
        self, tenant_id: uuid.UUID, resource_type: str, resource_id: uuid.UUID
    ) -> ResourceRecord | None: ...


class TenantWriteSession(Protocol):
    """The tenant-plane session surface ownership changes require.

    ``TenantSession`` satisfies this structurally; AccessControl never opens
    the tenant plane itself.
    """

    context: TenantContext

    async def execute(self, statement: sa.Executable) -> sa.Result[Any]: ...

    async def flush(self) -> None: ...


_HASHER = PasswordHasher()


def build_invitation_token() -> str:
    return f"inv_{secrets.token_hex(16)}_{secrets.token_hex(32)}"


def hash_invitation_secret(secret: str) -> str:
    return _HASHER.hash(secret)


def verify_invitation(token: str, token_id: str, stored_hash: str) -> bool:
    parts = token.split("_")
    if len(parts) != 3 or parts[0] != "inv" or parts[1] != token_id:
        return False
    try:
        return _HASHER.verify(stored_hash, parts[2])
    except (VerificationError, InvalidHashError):
        return False


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
        resource_lookup: ResourceLookup | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._catalog = catalog
        self._reader = reader
        self._cache = cache
        self._audit = audit
        self._registry = registry or ResourceTypeRegistry()
        self._scope_lookup = scope_lookup
        self._resource_lookup = resource_lookup

    @property
    def _catalog_codes(self) -> frozenset[str]:
        return frozenset(permission.code for permission in self._catalog.all())

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
        if record.tenant_id != tenant_id:
            raise CrossTenantReferenceError(
                f"{scope_type} scope {scope_id}", str(tenant_id), str(record.tenant_id)
            )
        if record.deleted:
            raise InvalidReference(f"{scope_type} scope is deleted: {scope_id}")

    async def _validate_scope_placement(
        self, tenant_id: uuid.UUID, scope_type: str, scope_id: uuid.UUID | None
    ) -> ScopeType:
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
        return scope

    async def _validate_resource(
        self, tenant_id: uuid.UUID, resource_type: str, resource_id: uuid.UUID
    ) -> None:
        if self._resource_lookup is None:
            raise AuthorizationError("resource validation is not configured")
        record = await self._resource_lookup(tenant_id, resource_type, resource_id)
        if record is None:
            raise InvalidReference(f"resource not found: {resource_type}:{resource_id}")
        if record.tenant_id != tenant_id:
            raise CrossTenantReferenceError(
                f"{resource_type} resource {resource_id}",
                str(tenant_id),
                str(record.tenant_id),
            )
        if record.deleted:
            raise InvalidReference(f"resource is deleted: {resource_type}:{resource_id}")

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
                session=session,
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
                session=session,
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
                session=session,
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
        scope = await self._validate_scope_placement(tenant_id, scope_type, scope_id)
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
                session=session,
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
                session=session,
            )
            await session.commit()

    async def _find_grant(
        self,
        session: ControlPlaneSession,
        tenant_id: uuid.UUID,
        *,
        resource_type: str,
        resource_id: uuid.UUID,
        principal_type: str,
        principal_id: uuid.UUID,
        permission: str,
    ) -> ResourceGrant | None:
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
        return existing

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
        await self._validate_resource(tenant_id, resource_type, resource_id)
        self._cache.invalidate()
        async with await self._session() as session:
            existing = await self._find_grant(
                session,
                tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                principal_type=principal_type,
                principal_id=principal_id,
                permission=permission,
            )
            if existing is not None:
                return existing
            grant = ResourceGrant(
                id=uuid7(),
                tenant_id=tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                principal_type=principal_type,
                principal_id=principal_id,
                permission_code=permission,
                created_by=actor_id,
            )
            inserted: uuid.UUID | None = (
                await session.execute(
                    pg_insert(ResourceGrant)
                    .values(
                        id=grant.id,
                        tenant_id=grant.tenant_id,
                        resource_type=grant.resource_type,
                        resource_id=grant.resource_id,
                        principal_type=grant.principal_type,
                        principal_id=grant.principal_id,
                        permission_code=grant.permission_code,
                        created_by=grant.created_by,
                    )
                    .on_conflict_do_nothing()
                    .returning(ResourceGrant.id)
                )
            ).scalar_one_or_none()
            if inserted is None:
                existing = await self._find_grant(
                    session,
                    tenant_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    principal_type=principal_type,
                    principal_id=principal_id,
                    permission=permission,
                )
                if existing is None:
                    raise AuthorizationError(
                        f"grant conflict without a stored row: {resource_type}:{resource_id}"
                    )
                return existing
            await self._audit.record(
                action="grant.created",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={
                    "resource": f"{resource_type}:{resource_id}",
                    "permission": permission,
                    "principal_id": str(principal_id),
                },
                session=session,
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
        await self._require_permission(tenant_id, "resource:share", actor_principal)
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
                session=session,
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
        await self._require_permission(context.tenant_id, "resource:share", actor_principal)
        if to_team_id is not None and to_organization_id is None:
            raise InvalidReference("team ownership requires an organization")
        if to_organization_id is not None:
            await self._validate_scope(context.tenant_id, "org", to_organization_id)
        if to_team_id is not None:
            await self._validate_scope(context.tenant_id, "team", to_team_id)
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
            await self._revoke_grants(
                session,
                context.tenant_id,
                ResourceGrant.resource_type == resource_type,
                ResourceGrant.resource_id == resource_id,
                actor_id=actor_id,
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
        await self._require_permission(context.tenant_id, "team:manage", actor_principal)
        await self._validate_scope(context.tenant_id, "org", to_organization_id)
        self._cache.invalidate()
        previous = (
            await session.execute(
                sa.select(Team.organization_id).where(
                    Team.tenant_id == context.tenant_id, Team.id == team_id
                )
            )
        ).scalar_one_or_none()
        if previous is None:
            raise InvalidReference(f"team not found: {team_id}")
        statement = (
            sa.update(Team)
            .where(Team.tenant_id == context.tenant_id, Team.id == team_id)
            .values(organization_id=to_organization_id)
            .execution_options(jdlib_scoped=True)
        )
        cascaded_tables: set[sa.Table] = set()
        for index, definition in enumerate(self._registry.all()):
            model = cast(Any, definition.model)
            if not (hasattr(model, "team_id") and hasattr(model, "organization_id")):
                continue
            if model.__table__ in cascaded_tables:
                continue
            cascaded_tables.add(model.__table__)
            cascade = (
                sa.update(model)
                .where(model.tenant_id == context.tenant_id, model.team_id == team_id)
                .values(organization_id=to_organization_id)
                .cte(f"moved_resource_{index}")
            )
            statement = statement.add_cte(cascade)
        await session.execute(statement)
        if revoke_grants:
            await self._revoke_team_grants(
                session, context.tenant_id, team_id, actor_id=actor_id
            )
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

    async def _revoke_grants(
        self,
        session: TenantWriteSession,
        tenant_id: uuid.UUID,
        *conditions: sa.ColumnElement[bool],
        actor_id: uuid.UUID | None,
    ) -> None:
        grant_ids = (
            await session.execute(
                sa.select(ResourceGrant.id).where(
                    ResourceGrant.tenant_id == tenant_id, *conditions
                )
            )
        ).scalars().all()
        for grant_id in grant_ids:
            await self._audit.record(
                action="grant.revoked",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"grant_id": str(grant_id)},
            )
        if grant_ids:
            await session.execute(
                sa.delete(ResourceGrant).where(
                    ResourceGrant.tenant_id == tenant_id, *conditions
                )
            )

    async def _revoke_team_grants(
        self,
        session: TenantWriteSession,
        tenant_id: uuid.UUID,
        team_id: uuid.UUID,
        *,
        actor_id: uuid.UUID | None,
    ) -> None:
        resource_ids_by_table: dict[sa.Table, list[uuid.UUID]] = {}
        for definition in self._registry.all():
            model = cast(Any, definition.model)
            if not hasattr(model, "team_id"):
                continue
            table: sa.Table = model.__table__
            if table not in resource_ids_by_table:
                resource_ids_by_table[table] = list(
                    (
                        await session.execute(
                            sa.select(model.id).where(model.team_id == team_id)
                        )
                    )
                    .scalars()
                    .all()
                )
            resource_ids = resource_ids_by_table[table]
            if not resource_ids:
                continue
            await self._revoke_grants(
                session,
                tenant_id,
                ResourceGrant.resource_type == definition.resource_type,
                ResourceGrant.resource_id.in_(resource_ids),
                actor_id=actor_id,
            )

    async def invite(
        self,
        tenant_id: uuid.UUID,
        *,
        email: str,
        role_id: uuid.UUID,
        scope_type: str,
        scope_id: uuid.UUID | None,
        invited_by: uuid.UUID | None,
        actor_principal: Principal,
        ttl: timedelta = timedelta(days=7),
    ) -> tuple[Invitation, str]:
        held = await self._require_permission(tenant_id, "member:invite", actor_principal)
        scope = await self._validate_scope_placement(tenant_id, scope_type, scope_id)
        token = build_invitation_token()
        token_id = token.split("_")[1]
        secret = token.rsplit("_", 1)[1]
        self._cache.invalidate()
        now = datetime.now(UTC)
        async with await self._session() as session:
            await self._lock(session, tenant_id)
            role = await session.get(Role, {"tenant_id": tenant_id, "id": role_id})
            if role is None:
                raise InvalidReference(f"role not found: {role_id}")
            codes = (
                await session.execute(
                    sa.select(RolePermission.permission_code).where(
                        RolePermission.tenant_id == tenant_id,
                        RolePermission.role_id == role_id,
                    )
                )
            ).scalars().all()
            for code in codes:
                permission = self._catalog.validate(code)
                if scope not in permission.allowed_scopes:
                    raise RoleScopeMismatch(f"{code} cannot be bound at {scope_type} scope")
            if role.name == "owner" and not self._catalog_codes <= held:
                raise AuthorizationError("only a full-catalog actor may assign the owner role")
            await self._require_subset(tenant_id, codes, actor_principal)
            conditions = [
                Invitation.tenant_id == tenant_id,
                Invitation.email == email,
                Invitation.scope_type == scope_type,
                Invitation.status == "pending",
            ]
            if scope_id is None:
                conditions.append(Invitation.scope_id.is_(None))
            else:
                conditions.append(Invitation.scope_id == scope_id)
            stale_ids = (
                await session.execute(sa.select(Invitation.id).where(*conditions))
            ).scalars().all()
            if stale_ids:
                await session.execute(
                    sa.update(Invitation)
                    .where(*conditions)
                    .values(status="revoked", revoked_at=now)
                )
                for stale_id in stale_ids:
                    await self._audit.record(
                        action="invitation.revoked",
                        tenant_id=tenant_id,
                        actor_id=invited_by,
                        metadata={"invitation_id": str(stale_id)},
                        session=session,
                    )
            invitation = Invitation(
                tenant_id=tenant_id,
                email=email,
                scope_type=scope_type,
                scope_id=scope_id,
                role_id=role_id,
                token_id=token_id,
                token_hash=hash_invitation_secret(secret),
                status="pending",
                expires_at=now + ttl,
                invited_by=invited_by,
            )
            session.add(invitation)
            await self._audit.record(
                action="invitation.created",
                tenant_id=tenant_id,
                actor_id=invited_by,
                metadata={"email": email, "role_id": str(role_id)},
                session=session,
            )
            await session.commit()
            return invitation, token

    async def accept_invitation(self, token: str, *, user_id: uuid.UUID) -> Membership:
        token_id = token.split("_")[1] if token.startswith("inv_") else ""
        self._cache.invalidate()
        async with await self._session() as session:
            invitation = (
                await session.execute(
                    sa.select(Invitation).where(Invitation.token_id == token_id)
                )
            ).scalar_one_or_none()
            if invitation is None or not verify_invitation(
                token, invitation.token_id, invitation.token_hash
            ):
                raise InvalidReference("invalid invitation token")
            now = datetime.now(UTC)
            if invitation.status != "pending":
                raise InvalidReference(f"invitation is {invitation.status}")
            if invitation.expires_at <= now:
                raise InvalidReference("invitation expired")
            claimed = cast(
                sa.CursorResult[Any],
                await session.execute(
                    sa.update(Invitation)
                    .where(
                        Invitation.tenant_id == invitation.tenant_id,
                        Invitation.id == invitation.id,
                        Invitation.status == "pending",
                    )
                    .values(status="accepted", accepted_at=now)
                    .execution_options(synchronize_session=False)
                ),
            )
            if claimed.rowcount != 1:
                current = (
                    await session.execute(
                        sa.select(Invitation.status).where(Invitation.id == invitation.id)
                    )
                ).scalar_one_or_none()
                raise InvalidReference(f"invitation is {current or 'unavailable'}")
            scope = await self._validate_scope_placement(
                invitation.tenant_id, invitation.scope_type, invitation.scope_id
            )
            codes = (
                await session.execute(
                    sa.select(RolePermission.permission_code).where(
                        RolePermission.tenant_id == invitation.tenant_id,
                        RolePermission.role_id == invitation.role_id,
                    )
                )
            ).scalars().all()
            for code in codes:
                permission = self._catalog.validate(code)
                if scope not in permission.allowed_scopes:
                    raise RoleScopeMismatch(
                        f"{code} cannot be bound at {invitation.scope_type} scope"
                    )
            membership = (
                await session.execute(
                    sa.select(Membership).where(
                        Membership.tenant_id == invitation.tenant_id,
                        Membership.user_id == user_id,
                    )
                )
            ).scalar_one_or_none()
            if membership is not None and membership.status != "active":
                raise InvalidReference(f"membership is {membership.status}")
            if membership is None:
                membership = Membership(
                    tenant_id=invitation.tenant_id,
                    user_id=user_id,
                    status="active",
                )
                session.add(membership)
                await session.flush()
            binding_conditions = [
                RoleBinding.tenant_id == invitation.tenant_id,
                RoleBinding.role_id == invitation.role_id,
                RoleBinding.principal_type == "user",
                RoleBinding.principal_id == user_id,
                RoleBinding.scope_type == invitation.scope_type,
            ]
            if invitation.scope_id is None:
                binding_conditions.append(RoleBinding.scope_id.is_(None))
            else:
                binding_conditions.append(RoleBinding.scope_id == invitation.scope_id)
            existing = (
                await session.execute(sa.select(RoleBinding).where(*binding_conditions))
            ).scalar_one_or_none()
            if existing is None:
                session.add(
                    RoleBinding(
                        tenant_id=invitation.tenant_id,
                        role_id=invitation.role_id,
                        principal_type="user",
                        principal_id=user_id,
                        scope_type=invitation.scope_type,
                        scope_id=invitation.scope_id,
                        created_by=invitation.invited_by,
                    )
                )
            await self._audit.record(
                action="invitation.accepted",
                tenant_id=invitation.tenant_id,
                actor_id=user_id,
                metadata={"invitation_id": str(invitation.id)},
                session=session,
            )
            await session.commit()
            return membership
