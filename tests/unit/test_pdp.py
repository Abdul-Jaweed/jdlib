import uuid

import pytest

from jdlib.authz.cache import AuthzCache
from jdlib.authz.pdp import DefaultPDP
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import Binding
from jdlib.authz.scopes import ResourceRef, ScopeRef
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy, ScopeType
from jdlib.errors import MissingTenantContext

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
USER_ID = uuid.uuid4()
RESOURCE_ID = uuid.uuid4()
_SESSION = object()
_TENANT_CHAIN = (ScopeRef(ScopeType.TENANT, None),)


def _context(principal: Principal) -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req",
        correlation_id="corr",
    )


class _Reader:
    def __init__(
        self,
        *,
        tenant_status: str = "active",
        principal_active: bool = True,
        membership_active: bool = True,
        role_permissions: dict[uuid.UUID, frozenset[str]] | None = None,
        bindings: list[tuple[uuid.UUID, ScopeType, uuid.UUID | None]] | None = None,
        grants: frozenset[str] | None = None,
    ) -> None:
        self.tenant_status = tenant_status
        self._principal_active = principal_active
        self._membership_active = membership_active
        self.role_permissions = role_permissions or {}
        self.bindings = bindings or []
        self.grants = grants or frozenset()

    async def tenant_status_of(self, tenant_id: uuid.UUID) -> str:
        return self.tenant_status

    async def principal_active(self, principal: Principal) -> bool:
        return self._principal_active

    async def membership_active(self, principal: Principal, tenant_id: uuid.UUID) -> bool:
        return self._membership_active

    async def bindings_for(self, principal, tenant_id, scope_chain):
        return [Binding(*b) for b in self.bindings if (b[1], b[2]) in scope_chain]

    async def permissions_for_roles(self, tenant_id, role_ids):
        return frozenset().union(
            *(self.role_permissions.get(role, frozenset()) for role in role_ids)
        )

    async def grants_for(self, principal, tenant_id, resource_type, resource_id):
        return self.grants


class _Scopes:
    def __init__(self, chain):
        self._chain = chain

    async def chain(self, session, target):
        return self._chain


def _pdp(reader, chain=_TENANT_CHAIN) -> DefaultPDP:
    return DefaultPDP(
        catalog=PermissionCatalog.with_builtins(),
        reader=reader,
        scopes=_Scopes(chain),
        cache=AuthzCache(),
    )


def _user(scopes: frozenset[str] | None = None) -> Principal:
    return Principal(kind=PrincipalKind.USER, id=USER_ID, user_id=USER_ID, scopes=scopes)


def test_cache_memoizes_until_invalidated():
    cache = AuthzCache()
    assert cache.get("k") is None
    cache.put("k", "v")
    assert cache.get("k") == "v"
    cache.invalidate()
    assert cache.get("k") is None
    cache.put("k", "v2")
    assert cache.get("k") is None


async def test_denies_when_tenant_not_active():
    decision = await _pdp(_Reader(tenant_status="suspended")).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=None,
    )
    assert decision.allowed is False
    assert decision.reason == "tenant_suspended"


async def test_denies_when_principal_inactive():
    decision = await _pdp(_Reader(principal_active=False)).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=None,
    )
    assert decision.reason == "principal_inactive"


async def test_denies_when_membership_inactive():
    decision = await _pdp(_Reader(membership_active=False)).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=None,
    )
    assert decision.reason == "membership_inactive"


async def test_allows_tenant_scope_binding():
    role_id = uuid.uuid4()
    reader = _Reader(
        bindings=[(role_id, ScopeType.TENANT, None)],
        role_permissions={role_id: frozenset({"resource:read"})},
    )
    decision = await _pdp(reader).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=_SESSION,
    )
    assert decision.allowed is True
    assert decision.matched[0].kind == "binding"


async def test_denies_without_session_for_scope_resolution():
    with pytest.raises(MissingTenantContext):
        await _pdp(_Reader()).evaluate(
            _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
            session=None,
        )


async def test_denies_without_allow():
    decision = await _pdp(_Reader()).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=_SESSION,
    )
    assert decision.allowed is False
    assert decision.reason == "no_allow"


async def test_grants_apply_only_to_the_exact_resource():
    reader = _Reader(grants=frozenset({"resource:read"}))
    decision = await _pdp(reader, chain=(ScopeRef(ScopeType.TENANT, None),)).evaluate(
        _user(),
        "resource:read",
        ResourceRef("invoice", RESOURCE_ID),
        _context(_user()),
        session=_SESSION,
    )
    assert decision.allowed is True
    assert any(rule.kind == "grant" for rule in decision.matched)


async def test_api_key_scopes_narrow_everything():
    role_id = uuid.uuid4()
    reader = _Reader(
        bindings=[(role_id, ScopeType.TENANT, None)],
        role_permissions={role_id: frozenset({"resource:read", "resource:delete"})},
        grants=frozenset({"resource:delete"}),
    )
    principal = Principal(
        kind=PrincipalKind.SERVICE_ACCOUNT,
        id=uuid.uuid4(),
        tenant_id=TENANT_ID,
        scopes=frozenset({"resource:read"}),
    )
    pdp = _pdp(reader)
    allowed = await pdp.evaluate(
        principal,
        "resource:read",
        ScopeRef(ScopeType.TENANT, None),
        _context(principal),
        session=_SESSION,
    )
    denied = await pdp.evaluate(
        principal,
        "resource:delete",
        ResourceRef("invoice", RESOURCE_ID),
        _context(principal),
        session=_SESSION,
    )
    assert allowed.allowed is True
    assert denied.allowed is False
    assert denied.reason == "outside_key_scopes"
