from __future__ import annotations

import uuid
from collections.abc import Callable, Collection, Mapping, Sequence
from typing import NamedTuple, Protocol

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import Principal, PrincipalKind
from jdlib.control.enums import ScopeType
from jdlib.control.models import Membership, ResourceGrant, RoleBinding, RolePermission
from jdlib.control.session import ControlPlaneSession


class Binding(NamedTuple):
    role_id: uuid.UUID
    scope_type: ScopeType
    scope_id: uuid.UUID | None


def principal_key(principal: Principal) -> uuid.UUID:
    if principal.kind is PrincipalKind.USER and principal.user_id is not None:
        return principal.user_id
    return principal.id


class AccessReader(Protocol):
    async def tenant_status_of(self, tenant_id: uuid.UUID) -> str: ...

    async def principal_active(self, principal: Principal) -> bool: ...

    async def service_account_active(
        self, tenant_id: uuid.UUID, service_account_id: uuid.UUID
    ) -> bool: ...

    async def membership_active(self, principal: Principal, tenant_id: uuid.UUID) -> bool: ...

    async def bindings_for(
        self,
        principal: Principal,
        tenant_id: uuid.UUID,
        scope_chain: Collection[tuple[ScopeType, uuid.UUID | None]],
    ) -> Sequence[Binding]: ...

    async def permissions_by_role(
        self, tenant_id: uuid.UUID, role_ids: Collection[uuid.UUID]
    ) -> Mapping[uuid.UUID, frozenset[str]]: ...

    async def grants_for(
        self, principal: Principal, tenant_id: uuid.UUID, resource_type: str, resource_id: uuid.UUID
    ) -> frozenset[str]: ...


class ControlAccessReader:
    """Reads authorization state from the control plane.

    Platform operators are never tenant-PDP principals (docs/jdlib/04 section
    6): ``principal_active`` and ``membership_active`` deny them explicitly
    without touching the database.
    """

    def __init__(self, session_factory: Callable[[], AsyncSession]) -> None:
        self._session_factory = session_factory

    async def _session(self) -> ControlPlaneSession:
        return ControlPlaneSession(self._session_factory())

    async def tenant_status_of(self, tenant_id: uuid.UUID) -> str:
        from jdlib.control.models import Tenant

        async with await self._session() as session:
            status = (
                await session.execute(sa.select(Tenant.status).where(Tenant.id == tenant_id))
            ).scalar_one_or_none()
        return status or "missing"

    async def principal_active(self, principal: Principal) -> bool:
        if principal.kind is PrincipalKind.PLATFORM_OPERATOR:
            return False
        if principal.kind is PrincipalKind.USER:
            from jdlib.control.models import User

            user_id = principal_key(principal)
            async with await self._session() as session:
                status = (
                    await session.execute(sa.select(User.status).where(User.id == user_id))
                ).scalar_one_or_none()
            return status == "active"
        from jdlib.control.models import ServiceAccount

        query = sa.select(ServiceAccount.status).where(
            ServiceAccount.id == principal_key(principal)
        )
        if principal.tenant_id is not None:
            query = query.where(ServiceAccount.tenant_id == principal.tenant_id)
        async with await self._session() as session:
            status = (await session.execute(query)).scalar_one_or_none()
        return status == "active"

    async def service_account_active(
        self, tenant_id: uuid.UUID, service_account_id: uuid.UUID
    ) -> bool:
        from jdlib.control.models import ServiceAccount

        async with await self._session() as session:
            status = (
                await session.execute(
                    sa.select(ServiceAccount.status).where(
                        ServiceAccount.tenant_id == tenant_id,
                        ServiceAccount.id == service_account_id,
                    )
                )
            ).scalar_one_or_none()
        return status == "active"

    async def membership_active(self, principal: Principal, tenant_id: uuid.UUID) -> bool:
        if principal.kind is PrincipalKind.PLATFORM_OPERATOR:
            return False
        if principal.kind is PrincipalKind.SERVICE_ACCOUNT:
            return True
        user_id = principal_key(principal)
        async with await self._session() as session:
            status = (
                await session.execute(
                    sa.select(Membership.status).where(
                        Membership.tenant_id == tenant_id,
                        Membership.user_id == user_id,
                    )
                )
            ).scalar_one_or_none()
        return status == "active"

    async def bindings_for(
        self,
        principal: Principal,
        tenant_id: uuid.UUID,
        scope_chain: Collection[tuple[ScopeType, uuid.UUID | None]],
    ) -> Sequence[Binding]:
        async with await self._session() as session:
            rows = (
                await session.execute(
                    sa.select(RoleBinding.role_id, RoleBinding.scope_type, RoleBinding.scope_id)
                    .where(
                        RoleBinding.tenant_id == tenant_id,
                        RoleBinding.principal_type == principal.kind.value,
                        RoleBinding.principal_id == principal_key(principal),
                    )
                )
            ).all()
        chain = set(scope_chain)
        bindings: list[Binding] = []
        for row in rows:
            # `tup()` rather than unpacking the Row: a fresh install resolves
            # `sqlalchemy>=2.0.30` to 2.1, where a Row is a sequence of unknown length to the
            # type checker, and unpacking it is an error it cannot see through.
            role_id, scope_type, scope_id = row.tup()
            scope = ScopeType(scope_type)
            if (scope, scope_id) in chain:
                bindings.append(Binding(role_id, scope, scope_id))
        return bindings

    async def permissions_by_role(
        self, tenant_id: uuid.UUID, role_ids: Collection[uuid.UUID]
    ) -> Mapping[uuid.UUID, frozenset[str]]:
        if not role_ids:
            return {}
        async with await self._session() as session:
            rows = (
                await session.execute(
                    sa.select(RolePermission.role_id, RolePermission.permission_code).where(
                        RolePermission.tenant_id == tenant_id,
                        RolePermission.role_id.in_(list(role_ids)),
                    )
                )
            ).all()
        by_role: dict[uuid.UUID, set[str]] = {}
        for row in rows:
            role_id, permission_code = row.tup()
            by_role.setdefault(role_id, set()).add(permission_code)
        return {role_id: frozenset(codes) for role_id, codes in by_role.items()}

    async def grants_for(
        self, principal: Principal, tenant_id: uuid.UUID, resource_type: str, resource_id: uuid.UUID
    ) -> frozenset[str]:
        async with await self._session() as session:
            rows = (
                await session.execute(
                    sa.select(ResourceGrant.permission_code).where(
                        ResourceGrant.tenant_id == tenant_id,
                        ResourceGrant.resource_type == resource_type,
                        ResourceGrant.resource_id == resource_id,
                        ResourceGrant.principal_type == principal.kind.value,
                        ResourceGrant.principal_id == principal_key(principal),
                    )
                )
            ).scalars().all()
        return frozenset(rows)
