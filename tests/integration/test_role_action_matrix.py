import uuid
from dataclasses import dataclass

import sqlalchemy as sa

from jdlib.authz.access import AccessControl
from jdlib.authz.cache import AuthzCache
from jdlib.authz.pdp import Decision, DefaultPDP
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.authz.resource_types import ResourceTypeDefinition, ResourceTypeRegistry
from jdlib.authz.scopes import ResourceRef, ScopeRef, ScopeResolver, Target
from jdlib.context import PlacementStrategy, Principal, PrincipalKind, TenantContext
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.enums import ScopeType
from jdlib.control.models import (
    Membership,
    Role,
    RoleBinding,
    RolePermission,
    ServiceAccount,
    Tenant,
    User,
)
from jdlib.models.org import Organization, Team
from jdlib.persistence.session import TenantSession
from tests.integration.test_access_bindings import _TenantScopeLookup
from tests.support.invoice import Invoice

TENANT_SCHEMA = "jt_test"

ALL_CODES = frozenset(permission.code for permission in PermissionCatalog.with_builtins().all())
TEMPLATES = {
    "owner": ALL_CODES,
    "admin": ALL_CODES - {"tenant:manage"},
    "member": frozenset({"resource:read", "resource:create", "resource:update"}),
    "viewer": frozenset({"resource:read"}),
}
ACTIONS = (
    "resource:read",
    "resource:update",
    "resource:delete",
    "member:invite",
    "role:manage",
    "tenant:manage",
    "resource:share",
)
RESOURCE_ACTIONS = frozenset(
    {"resource:read", "resource:update", "resource:delete", "resource:share"}
)
EXPECTED = {
    "owner": frozenset(ACTIONS),
    "admin": frozenset(ACTIONS) - {"tenant:manage"},
    "member": frozenset({"resource:read", "resource:update"}),
    "viewer": frozenset({"resource:read"}),
    "service_account": frozenset(),
    "platform_operator": frozenset(),
}


@dataclass(frozen=True, slots=True)
class _World:
    tenant_id: uuid.UUID
    team_id: uuid.UUID
    invoice_id: uuid.UUID
    user_ids: dict[str, uuid.UUID]
    principals: dict[str, Principal]
    pdp: DefaultPDP


def _context(tenant_id: uuid.UUID, principal: Principal) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug="matrix",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req",
        correlation_id="corr",
    )


async def _tenant_session(
    session_factory, tenant_id: uuid.UUID, principal: Principal
) -> TenantSession:
    raw = session_factory()
    await raw.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
    return TenantSession(raw, _context(tenant_id, principal))


def _target(world: _World, action: str) -> Target:
    if action in RESOURCE_ACTIONS:
        return ResourceRef("invoice", world.invoice_id)
    return ScopeRef(ScopeType.TENANT, None)


async def _seed(control_session_factory, session_factory) -> _World:
    tenant_id, org_id, team_id, invoice_id = (uuid.uuid4() for _ in range(4))
    user_ids = {
        "owner": uuid.uuid4(),
        "admin": uuid.uuid4(),
        "member": uuid.uuid4(),
        "viewer": uuid.uuid4(),
    }
    principals = {
        name: Principal(kind=PrincipalKind.USER, id=user_id, user_id=user_id)
        for name, user_id in user_ids.items()
    }
    account_id = uuid.uuid4()
    principals["service_account"] = Principal(
        kind=PrincipalKind.SERVICE_ACCOUNT, id=account_id, tenant_id=tenant_id
    )
    principals["platform_operator"] = Principal(
        kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4()
    )
    role_ids = {name: uuid.uuid4() for name in TEMPLATES}
    binding_scopes = {
        "owner": ("tenant", None),
        "admin": ("tenant", None),
        "member": ("team", team_id),
        "viewer": ("org", org_id),
    }
    async with control_session_factory() as session:
        session.add(
            Tenant(
                id=tenant_id,
                slug=f"matrix-{tenant_id.hex[:8]}",
                name="Matrix",
                status="active",
            )
        )
        for user_id in user_ids.values():
            session.add(User(id=user_id, status="active"))
        await session.flush()
        for name, codes in TEMPLATES.items():
            session.add(Role(tenant_id=tenant_id, id=role_ids[name], name=name, is_system=True))
            for code in sorted(codes):
                session.add(
                    RolePermission(
                        tenant_id=tenant_id, role_id=role_ids[name], permission_code=code
                    )
                )
        await session.flush()
        for name, user_id in user_ids.items():
            scope_type, scope_id = binding_scopes[name]
            session.add(
                Membership(
                    tenant_id=tenant_id, id=uuid.uuid4(), user_id=user_id, status="active"
                )
            )
            session.add(
                RoleBinding(
                    tenant_id=tenant_id,
                    id=uuid.uuid4(),
                    role_id=role_ids[name],
                    principal_type="user",
                    principal_id=user_id,
                    scope_type=scope_type,
                    scope_id=scope_id,
                )
            )
        session.add(
            ServiceAccount(tenant_id=tenant_id, id=account_id, name="matrix-bot", status="active")
        )
        await session.commit()

    async with await _tenant_session(session_factory, tenant_id, principals["owner"]) as session:
        await session.add(Organization(id=org_id, name="Matrix Org", slug=f"org-{org_id.hex[:6]}"))
        await session.flush()
        await session.add(
            Team(
                id=team_id,
                organization_id=org_id,
                name="Matrix Team",
                slug=f"team-{team_id.hex[:6]}",
            )
        )
        await session.flush()
        await session.add(
            Invoice(
                id=invoice_id,
                number=f"INV-{invoice_id.hex[:6]}",
                organization_id=org_id,
                team_id=team_id,
            )
        )
        await session.commit()

    registry = ResourceTypeRegistry()
    registry.register(
        ResourceTypeDefinition(
            "invoice",
            Invoice,
            tenant_owned=True,
            tenant_routed=True,
            permission_namespace="invoice",
        )
    )
    pdp = DefaultPDP(
        catalog=PermissionCatalog.with_builtins(),
        reader=ControlAccessReader(control_session_factory),
        scopes=ScopeResolver(registry),
        cache=AuthzCache(),
    )
    return _World(
        tenant_id=tenant_id,
        team_id=team_id,
        invoice_id=invoice_id,
        user_ids=user_ids,
        principals=principals,
        pdp=pdp,
    )


async def test_role_action_matrix(control_session_factory, session_factory):
    world = await _seed(control_session_factory, session_factory)
    decisions: dict[tuple[str, str], Decision] = {}
    actual: dict[str, frozenset[str]] = {}
    async with await _tenant_session(
        session_factory, world.tenant_id, world.principals["owner"]
    ) as session:
        for name, principal in world.principals.items():
            allowed: set[str] = set()
            for action in ACTIONS:
                decision = await world.pdp.evaluate(
                    principal,
                    action,
                    _target(world, action),
                    _context(world.tenant_id, principal),
                    session=session,
                )
                decisions[(name, action)] = decision
                if decision.allowed:
                    allowed.add(action)
            actual[name] = frozenset(allowed)

    assert actual == EXPECTED
    assert decisions[("platform_operator", "resource:read")].reason == "principal_inactive"
    assert decisions[("service_account", "resource:read")].reason == "no_allow"


async def test_access_control_invalidates_the_shared_pdp_cache(
    control_session_factory, session_factory
):
    world = await _seed(control_session_factory, session_factory)
    control = AccessControl(
        session_factory=control_session_factory,
        catalog=PermissionCatalog.with_builtins(),
        reader=ControlAccessReader(control_session_factory),
        cache=world.pdp.cache,
        audit=RecordingPlatformAudit(),
        scope_lookup=_TenantScopeLookup(session_factory),
    )
    member = world.principals["member"]
    owner = world.principals["owner"]
    target = ResourceRef("invoice", world.invoice_id)
    context = _context(world.tenant_id, member)
    async with await _tenant_session(session_factory, world.tenant_id, member) as session:
        before = await world.pdp.evaluate(
            member, "resource:share", target, context, session=session
        )
        assert before.allowed is False

        role = await control.create_role(
            world.tenant_id,
            "sharer",
            {"resource:share"},
            actor_id=world.user_ids["owner"],
            actor_principal=owner,
        )
        await control.bind_role(
            world.tenant_id,
            role.id,
            principal_type="user",
            principal_id=world.user_ids["member"],
            scope_type="team",
            scope_id=world.team_id,
            actor_id=world.user_ids["owner"],
            actor_principal=owner,
        )

        after = await world.pdp.evaluate(member, "resource:share", target, context, session=session)
        assert after.allowed is True
