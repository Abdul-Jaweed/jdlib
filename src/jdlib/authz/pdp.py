from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import NamedTuple, Protocol, TypeVar, cast

from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import AccessReader
from jdlib.authz.scopes import ResourceRef, ScopeResolver, Target
from jdlib.context import Principal, TenantContext
from jdlib.errors import MissingTenantContext
from jdlib.persistence.session import TenantSession

_T = TypeVar("_T")


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
    """Tenant-plane policy decision point.

    Gates run in the frozen precedence order of docs/jdlib/04 section 2:
    principal active, tenant active, membership active, binding validity, then
    permission.

    The injected ``AuthzCache`` is request-scoped only and must never be shared
    across requests: this class memoizes the status gates, scope chains,
    bindings, per-role permissions, and grants through it. ``invalidate()``
    clears the memo and, fail-safe, does not re-enable it within the request;
    there is no cross-request authorization cache in v1.
    """

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

    async def _remember(self, key: tuple[object, ...], produce: Callable[[], Awaitable[_T]]) -> _T:
        cached = self._cache.get(key)
        if cached is not None:
            return cast(_T, cached)
        value = await produce()
        self._cache.put(key, value)
        return value

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
        principal_active = await self._remember(
            ("principal_active", principal),
            lambda: self._reader.principal_active(principal),
        )
        if not principal_active:
            return Decision(False, "principal_inactive", ())
        tenant_status = await self._remember(
            ("tenant_status", tenant_id),
            lambda: self._reader.tenant_status_of(tenant_id),
        )
        if tenant_status != "active":
            return Decision(False, "tenant_suspended", ())
        membership_active = await self._remember(
            ("membership_active", principal, tenant_id),
            lambda: self._reader.membership_active(principal, tenant_id),
        )
        if not membership_active:
            return Decision(False, "membership_inactive", ())
        if session is None:
            raise MissingTenantContext("PDP requires a tenant session for scope resolution")
        chain = await self._remember(
            ("scope_chain", target),
            lambda: self._scopes.chain(cast(TenantSession, session), target),
        )
        scope_chain = frozenset((scope.type, scope.id) for scope in chain)
        bindings = await self._remember(
            ("bindings", tenant_id, principal, scope_chain),
            lambda: self._reader.bindings_for(principal, tenant_id, scope_chain),
        )
        role_ids = frozenset(binding.role_id for binding in bindings)
        perms_by_role = await self._remember(
            ("role_permissions", tenant_id, role_ids),
            lambda: self._reader.permissions_by_role(tenant_id, role_ids),
        )
        role_perms = frozenset(code for codes in perms_by_role.values() for code in codes)
        matched = [
            MatchedRule(
                "binding",
                f"role {binding.role_id} at {binding.scope_type.value}:{binding.scope_id}",
            )
            for binding in bindings
            if permission in perms_by_role.get(binding.role_id, frozenset())
        ]
        granted: frozenset[str] = frozenset()
        if isinstance(target, ResourceRef):
            granted = await self._remember(
                ("grants", tenant_id, principal, target.resource_type, target.resource_id),
                lambda: self._reader.grants_for(
                    principal, tenant_id, target.resource_type, target.resource_id
                ),
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
