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
OTHER_RESOURCE_ID = uuid.uuid4()
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
        granted_resource_ids: set[uuid.UUID] | None = None,
    ) -> None:
        self.tenant_status = tenant_status
        self._principal_active = principal_active
        self._membership_active = membership_active
        self.role_permissions = role_permissions or {}
        self.bindings = bindings or []
        self.grants = grants or frozenset()
        self.granted_resource_ids = granted_resource_ids

    async def tenant_status_of(self, tenant_id: uuid.UUID) -> str:
        return self.tenant_status

    async def principal_active(self, principal: Principal) -> bool:
        return self._principal_active

    async def membership_active(self, principal: Principal, tenant_id: uuid.UUID) -> bool:
        return self._membership_active

    async def bindings_for(self, principal, tenant_id, scope_chain):
        return [Binding(*b) for b in self.bindings if (b[1], b[2]) in scope_chain]

    async def permissions_by_role(self, tenant_id, role_ids):
        return {role_id: self.role_permissions.get(role_id, frozenset()) for role_id in role_ids}

    async def grants_for(self, principal, tenant_id, resource_type, resource_id):
        if self.granted_resource_ids is not None and resource_id not in self.granted_resource_ids:
            return frozenset()
        return self.grants


class _CountingReader(_Reader):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.calls: dict[str, int] = {}

    def _count(self, name: str) -> None:
        self.calls[name] = self.calls.get(name, 0) + 1

    async def tenant_status_of(self, tenant_id: uuid.UUID) -> str:
        self._count("tenant_status_of")
        return await super().tenant_status_of(tenant_id)

    async def principal_active(self, principal: Principal) -> bool:
        self._count("principal_active")
        return await super().principal_active(principal)

    async def membership_active(self, principal: Principal, tenant_id: uuid.UUID) -> bool:
        self._count("membership_active")
        return await super().membership_active(principal, tenant_id)

    async def bindings_for(self, principal, tenant_id, scope_chain):
        self._count("bindings_for")
        return await super().bindings_for(principal, tenant_id, scope_chain)

    async def permissions_by_role(self, tenant_id, role_ids):
        self._count("permissions_by_role")
        return await super().permissions_by_role(tenant_id, role_ids)

    async def grants_for(self, principal, tenant_id, resource_type, resource_id):
        self._count("grants_for")
        return await super().grants_for(principal, tenant_id, resource_type, resource_id)


class _Scopes:
    def __init__(self, chain):
        self._chain = chain
        self.calls = 0

    async def chain(self, session, target):
        self.calls += 1
        return self._chain


def _pdp(reader, chain=_TENANT_CHAIN, cache=None, scopes=None) -> DefaultPDP:
    return DefaultPDP(
        catalog=PermissionCatalog.with_builtins(),
        reader=reader,
        scopes=scopes or _Scopes(chain),
        cache=cache or AuthzCache(),
    )


def _user(scopes: frozenset[str] | None = None) -> Principal:
    return Principal(kind=PrincipalKind.USER, id=USER_ID, user_id=USER_ID, scopes=scopes)


def _service_account(scopes: frozenset[str] | None = None) -> Principal:
    return Principal(
        kind=PrincipalKind.SERVICE_ACCOUNT, id=uuid.uuid4(), tenant_id=TENANT_ID, scopes=scopes
    )


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


async def test_principal_inactive_precedes_tenant_suspended():
    decision = await _pdp(_Reader(tenant_status="suspended", principal_active=False)).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=None,
    )
    assert decision.allowed is False
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


async def test_matched_only_includes_bindings_whose_role_grants_permission():
    read_role = uuid.uuid4()
    other_role = uuid.uuid4()
    team_id = uuid.uuid4()
    reader = _Reader(
        bindings=[
            (other_role, ScopeType.TENANT, None),
            (read_role, ScopeType.TEAM, team_id),
        ],
        role_permissions={
            read_role: frozenset({"resource:read"}),
            other_role: frozenset({"resource:update"}),
        },
    )
    chain = (ScopeRef(ScopeType.TENANT, None), ScopeRef(ScopeType.TEAM, team_id))
    decision = await _pdp(reader, chain=chain).evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TEAM, team_id), _context(_user()),
        session=_SESSION,
    )
    assert decision.allowed is True
    assert len(decision.matched) == 1
    assert decision.matched[0].kind == "binding"
    assert decision.matched[0].detail == f"role {read_role} at team:{team_id}"


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
    reader = _Reader(grants=frozenset({"resource:read"}), granted_resource_ids={RESOURCE_ID})
    pdp = _pdp(reader)
    allowed = await pdp.evaluate(
        _user(),
        "resource:read",
        ResourceRef("invoice", RESOURCE_ID),
        _context(_user()),
        session=_SESSION,
    )
    denied = await pdp.evaluate(
        _user(),
        "resource:read",
        ResourceRef("invoice", OTHER_RESOURCE_ID),
        _context(_user()),
        session=_SESSION,
    )
    assert allowed.allowed is True
    assert any(rule.kind == "grant" for rule in allowed.matched)
    assert denied.allowed is False
    assert denied.reason == "no_allow"


async def test_key_scopes_cannot_widen_bindings():
    role_id = uuid.uuid4()
    reader = _Reader(
        bindings=[(role_id, ScopeType.TENANT, None)],
        role_permissions={role_id: frozenset({"resource:read"})},
    )
    principal = _service_account(scopes=frozenset({"resource:read", "resource:update"}))
    decision = await _pdp(reader).evaluate(
        principal, "resource:update", ScopeRef(ScopeType.TENANT, None), _context(principal),
        session=_SESSION,
    )
    assert decision.allowed is False
    assert decision.reason == "no_allow"


async def test_empty_key_scopes_deny_everything():
    role_id = uuid.uuid4()
    reader = _Reader(
        bindings=[(role_id, ScopeType.TENANT, None)],
        role_permissions={role_id: frozenset({"resource:read"})},
    )
    principal = _service_account(scopes=frozenset())
    decision = await _pdp(reader).evaluate(
        principal, "resource:read", ScopeRef(ScopeType.TENANT, None), _context(principal),
        session=_SESSION,
    )
    assert decision.allowed is False
    assert decision.reason == "outside_key_scopes"


async def test_api_key_scopes_narrow_everything():
    role_id = uuid.uuid4()
    reader = _Reader(
        bindings=[(role_id, ScopeType.TENANT, None)],
        role_permissions={role_id: frozenset({"resource:read", "resource:delete"})},
        grants=frozenset({"resource:delete"}),
    )
    principal = _service_account(scopes=frozenset({"resource:read"}))
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


async def test_evaluate_memoizes_reader_and_scope_calls():
    role_id = uuid.uuid4()
    reader = _CountingReader(
        bindings=[(role_id, ScopeType.TENANT, None)],
        role_permissions={role_id: frozenset({"resource:read"})},
        grants=frozenset({"resource:read"}),
        granted_resource_ids={RESOURCE_ID},
    )
    scopes = _Scopes(_TENANT_CHAIN)
    pdp = _pdp(reader, scopes=scopes)
    principal = _user()
    for _ in range(3):
        decision = await pdp.evaluate(
            principal,
            "resource:read",
            ResourceRef("invoice", RESOURCE_ID),
            _context(principal),
            session=_SESSION,
        )
        assert decision.allowed is True
    assert reader.calls == {
        "tenant_status_of": 1,
        "principal_active": 1,
        "membership_active": 1,
        "bindings_for": 1,
        "permissions_by_role": 1,
        "grants_for": 1,
    }
    assert scopes.calls == 1


async def test_cache_invalidate_forces_refetch():
    role_id = uuid.uuid4()
    reader = _CountingReader(
        bindings=[(role_id, ScopeType.TENANT, None)],
        role_permissions={role_id: frozenset({"resource:read"})},
    )
    cache = AuthzCache()
    pdp = _pdp(reader, cache=cache)
    for _ in range(2):
        await pdp.evaluate(
            _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
            session=_SESSION,
        )
    assert reader.calls["bindings_for"] == 1
    cache.invalidate()
    await pdp.evaluate(
        _user(), "resource:read", ScopeRef(ScopeType.TENANT, None), _context(_user()),
        session=_SESSION,
    )
    assert reader.calls["bindings_for"] == 2
    assert reader.calls["principal_active"] == 2
