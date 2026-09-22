from __future__ import annotations

import uuid
from collections.abc import Callable, Collection

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import AccessReader
from jdlib.authz.resource_types import ResourceTypeRegistry
from jdlib.context import Principal
from jdlib.control.audit import PlatformAudit
from jdlib.control.enums import ScopeType
from jdlib.control.models import (
    Invitation,
    Membership,
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
    RoleScopeMismatch,
)


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
    ) -> None:
        self._session_factory = session_factory
        self._catalog = catalog
        self._reader = reader
        self._cache = cache
        self._audit = audit
        self._registry = registry or ResourceTypeRegistry()

    async def _session(self) -> ControlPlaneSession:
        return ControlPlaneSession(self._session_factory())

    async def actor_permissions(self, tenant_id: uuid.UUID, principal: Principal) -> frozenset[str]:
        bindings = await self._reader.bindings_for(
            principal, tenant_id, {(ScopeType.TENANT, None)}
        )
        by_role = await self._reader.permissions_by_role(
            tenant_id, [binding.role_id for binding in bindings]
        )
        return frozenset().union(*by_role.values()) if by_role else frozenset()

    async def _require_subset(
        self, tenant_id: uuid.UUID, permissions: Collection[str], principal: Principal
    ) -> None:
        held = await self.actor_permissions(tenant_id, principal)
        missing = set(permissions) - held
        if missing:
            raise AuthorizationError(f"missing permissions: {sorted(missing)}")

    def _validate_codes(self, permissions: Collection[str]) -> None:
        for code in permissions:
            self._catalog.validate(code)

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
        self._validate_codes(permissions)
        await self._require_subset(tenant_id, permissions, actor_principal)
        self._cache.invalidate()
        async with await self._session() as session:
            role: Role | None = await session.get(Role, {"tenant_id": tenant_id, "id": role_id})
            if role is None:
                raise InvalidReference(f"role not found: {role_id}")
            if role.is_system:
                raise AuthorizationError("system roles are immutable")
            await session.execute(
                sa.delete(RolePermission).where(
                    RolePermission.tenant_id == tenant_id, RolePermission.role_id == role_id
                )
            )
            for code in permissions:
                session.add(
                    RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code=code)
                )
            await self._audit.record(
                action="role.permissions_changed",
                tenant_id=tenant_id,
                actor_id=actor_id,
                metadata={"role_id": str(role_id), "permissions": sorted(permissions)},
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
                        Invitation.status == "pending",
                    )
                )
            ).scalar_one()
            if bindings or invitations:
                raise AuthorizationError("role has bindings or pending invitations")
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
        if scope_type == "tenant" and scope_id is not None:
            raise InvalidReference("tenant scope must not carry a scope id")
        if scope_type in {"org", "team"} and scope_id is None:
            raise InvalidReference(f"{scope_type} scope requires a scope id")
        async with await self._session() as session:
            role = await session.get(Role, {"tenant_id": tenant_id, "id": role_id})
            if role is None:
                raise InvalidReference(f"role not found: {role_id}")
            codes = (
                await session.execute(
                    sa.select(RolePermission.permission_code).where(
                        RolePermission.tenant_id == tenant_id, RolePermission.role_id == role_id
                    )
                )
            ).scalars().all()
            for code in codes:
                permission = self._catalog.validate(code)
                if ScopeType(scope_type) not in permission.allowed_scopes:
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
