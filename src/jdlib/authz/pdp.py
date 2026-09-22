from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple, Protocol, cast

from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import AccessReader
from jdlib.authz.scopes import ResourceRef, ScopeResolver, Target
from jdlib.context import Principal, TenantContext
from jdlib.errors import MissingTenantContext
from jdlib.persistence.session import TenantSession


class MatchedRule(NamedTuple):
    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    matched: tuple[MatchedRule, ...]


class PolicyDecisionPoint(Protocol):
    async def evaluate(
        self,
        principal: Principal,
        permission: str,
        target: Target,
        context: TenantContext,
        *,
        session: object,
    ) -> Decision: ...


class DefaultPDP:
    def __init__(
        self,
        *,
        catalog: PermissionCatalog,
        reader: AccessReader,
        scopes: ScopeResolver,
        cache: AuthzCache | None = None,
    ) -> None:
        self._catalog = catalog
        self._reader = reader
        self._scopes = scopes
        self._cache = cache or AuthzCache()

    async def evaluate(
        self,
        principal: Principal,
        permission: str,
        target: Target,
        context: TenantContext,
        *,
        session: object,
    ) -> Decision:
        self._catalog.validate(permission)
        tenant_id = context.tenant_id
        if await self._reader.tenant_status_of(tenant_id) != "active":
            return Decision(False, "tenant_suspended", ())
        if not await self._reader.principal_active(principal):
            return Decision(False, "principal_inactive", ())
        if not await self._reader.membership_active(principal, tenant_id):
            return Decision(False, "membership_inactive", ())
        if session is None:
            raise MissingTenantContext("PDP requires a tenant session for scope resolution")
        chain = await self._scopes.chain(cast(TenantSession, session), target)
        scope_chain = {(scope.type, scope.id) for scope in chain}
        bindings = await self._reader.bindings_for(principal, tenant_id, scope_chain)
        role_perms = await self._reader.permissions_for_roles(
            tenant_id, [binding.role_id for binding in bindings]
        )
        matched = [
            MatchedRule("binding", f"role {binding.role_id} at {binding.scope_type.value}")
            for binding in bindings
            if permission in role_perms
        ]
        granted: frozenset[str] = frozenset()
        if isinstance(target, ResourceRef):
            granted = await self._reader.grants_for(
                principal, tenant_id, target.resource_type, target.resource_id
            )
            if permission in granted:
                matched.append(
                    MatchedRule("grant", f"{target.resource_type}:{target.resource_id}")
                )
        base = role_perms | granted
        if principal.scopes is not None:
            if permission not in principal.scopes:
                return Decision(False, "outside_key_scopes", tuple(matched))
            base = base & principal.scopes
        if permission in base:
            return Decision(True, "allowed", tuple(matched))
        return Decision(False, "no_allow", tuple(matched))
