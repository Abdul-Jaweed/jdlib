import uuid
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa

from jdlib.authz.access import AccessControl, ScopeRecord
from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.enums import PlacementStrategy
from jdlib.control.models import (
    Membership,
    Role,
    RoleBinding,
    RolePermission,
    ServiceAccount,
    Tenant,
    User,
)
from jdlib.errors import (
    AuthorizationError,
    CrossTenantReferenceError,
    InvalidReference,
    RoleEscalationBlocked,
    RoleScopeMismatch,
)
from jdlib.models.org import Organization, Team
from jdlib.persistence.session import TenantSession

TENANT_SCHEMA = "jt_test"

OWNER_CODES = {
    "tenant:manage",
    "member:manage",
    "role:manage",
    "org:manage",
    "team:manage",
    "resource:read",
    "resource:share",
}


def _access(
    control_session_factory, *, audit: RecordingPlatformAudit | None = None
) -> AccessControl:
    return AccessControl(
        session_factory=control_session_factory,
        catalog=PermissionCatalog.with_builtins(),
        reader=ControlAccessReader(control_session_factory),
        cache=AuthzCache(),
        audit=audit or RecordingPlatformAudit(),
        scope_lookup=_TenantScopeLookup(control_session_factory),
    )


async def _tenant(control_session_factory) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"bd-{tenant_id.hex[:8]}", name="BD", status="active")
        )
        await session.commit()
    return tenant_id


def _tenant_context(tenant_id: uuid.UUID) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug="bd",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
    )


async def _tenant_session(session_factory, tenant_id: uuid.UUID) -> TenantSession:
    raw = session_factory()
    await raw.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
    return TenantSession(raw, _tenant_context(tenant_id))


class _TenantScopeLookup:
    """Test ScopeLookup backed by a TenantSession (I11/L14)."""

    _MODELS = {"org": Organization, "team": Team}

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    async def __call__(
        self, tenant_id: uuid.UUID, scope_type: str, scope_id: uuid.UUID
    ) -> ScopeRecord | None:
        model = self._MODELS[scope_type]
        async with await _tenant_session(self._session_factory, tenant_id) as session:
            row = await session.get(model, scope_id)
            if row is not None:
                return ScopeRecord(tenant_id=row.tenant_id, deleted=row.deleted_at is not None)
        raw = self._session_factory()
        try:
            await raw.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
            owner = (
                await raw.execute(sa.select(model.tenant_id).where(model.id == scope_id))
            ).scalar_one_or_none()
        finally:
            await raw.close()
        if owner is None:
            return None
        return ScopeRecord(tenant_id=owner, deleted=False)


async def _org(
    control_session_factory, tenant_id: uuid.UUID, *, deleted: bool = False
) -> uuid.UUID:
    org_id = uuid.uuid4()
    async with await _tenant_session(control_session_factory, tenant_id) as session:
        await session.add(
            Organization(
                id=org_id,
                name="BD Org",
                slug=f"org-{org_id.hex[:6]}",
                deleted_at=datetime.now(UTC) if deleted else None,
            )
        )
        await session.commit()
    return org_id


async def _team(control_session_factory, tenant_id: uuid.UUID) -> uuid.UUID:
    team_id = uuid.uuid4()
    org_id = await _org(control_session_factory, tenant_id)
    async with await _tenant_session(control_session_factory, tenant_id) as session:
        await session.add(
            Team(
                id=team_id,
                organization_id=org_id,
                name="BD Team",
                slug=f"team-{team_id.hex[:6]}",
            )
        )
        await session.commit()
    return team_id


async def _seed_actor(
    control_session_factory,
    tenant_id: uuid.UUID,
    *,
    name: str,
    codes: set[str],
) -> tuple[Principal, uuid.UUID, uuid.UUID]:
    principal = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    role_id = uuid.uuid4()
    binding_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=principal.user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=role_id, name=name))
        await session.flush()
        session.add(
            Membership(
                tenant_id=tenant_id, id=uuid.uuid4(), user_id=principal.user_id, status="active"
            )
        )
        for code in codes:
            session.add(
                RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code=code)
            )
        session.add(
            RoleBinding(
                tenant_id=tenant_id,
                id=binding_id,
                role_id=role_id,
                principal_type="user",
                principal_id=principal.user_id,
                scope_type="tenant",
            )
        )
        await session.commit()
    return principal, role_id, binding_id


async def _owner(control_session_factory, tenant_id: uuid.UUID) -> tuple[Principal, uuid.UUID]:
    owner, role_id, _ = await _seed_actor(
        control_session_factory,
        tenant_id,
        name=f"owner-{uuid.uuid4().hex[:6]}",
        codes=OWNER_CODES,
    )
    return owner, role_id


async def _full_actor(
    control_session_factory, tenant_id: uuid.UUID, *, name: str
) -> tuple[Principal, uuid.UUID, uuid.UUID]:
    codes = {permission.code for permission in PermissionCatalog.with_builtins().all()}
    return await _seed_actor(control_session_factory, tenant_id, name=name, codes=codes)


async def _member(control_session_factory, tenant_id: uuid.UUID) -> Principal:
    member = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    async with control_session_factory() as session:
        session.add(User(id=member.user_id, status="active"))
        await session.flush()
        session.add(
            Membership(
                tenant_id=tenant_id, id=uuid.uuid4(), user_id=member.user_id, status="active"
            )
        )
        await session.commit()
    return member


async def test_tenant_permission_cannot_be_team_scoped(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id,
        "tenant-admin",
        {"tenant:manage"},
        actor_id=owner.user_id,
        actor_principal=owner,
    )
    member = await _member(control_session_factory, tenant_id)
    team_id = await _team(control_session_factory, tenant_id)
    with pytest.raises(RoleScopeMismatch):
        await control.bind_role(
            tenant_id,
            role.id,
            principal_type="user",
            principal_id=member.user_id,
            scope_type="team",
            scope_id=team_id,
            actor_id=owner.user_id,
            actor_principal=owner,
        )


async def test_bind_team_scope_succeeds_with_real_team(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "team-manager", {"team:manage"}, actor_id=owner.user_id, actor_principal=owner
    )
    member = await _member(control_session_factory, tenant_id)
    team_id = await _team(control_session_factory, tenant_id)
    binding = await control.bind_role(
        tenant_id,
        role.id,
        principal_type="user",
        principal_id=member.user_id,
        scope_type="team",
        scope_id=team_id,
        actor_id=owner.user_id,
        actor_principal=owner,
    )
    assert binding.scope_type == "team"
    assert binding.scope_id == team_id


async def test_bind_scope_reference_must_exist(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "org-manager", {"org:manage"}, actor_id=owner.user_id, actor_principal=owner
    )
    member = await _member(control_session_factory, tenant_id)
    with pytest.raises(InvalidReference):
        await control.bind_role(
            tenant_id,
            role.id,
            principal_type="user",
            principal_id=member.user_id,
            scope_type="org",
            scope_id=uuid.uuid4(),
            actor_id=owner.user_id,
            actor_principal=owner,
        )


async def test_bind_scope_reference_must_belong_to_tenant(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    other_tenant = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "org-manager", {"org:manage"}, actor_id=owner.user_id, actor_principal=owner
    )
    member = await _member(control_session_factory, tenant_id)
    foreign_org = await _org(control_session_factory, other_tenant)
    with pytest.raises(CrossTenantReferenceError):
        await control.bind_role(
            tenant_id,
            role.id,
            principal_type="user",
            principal_id=member.user_id,
            scope_type="org",
            scope_id=foreign_org,
            actor_id=owner.user_id,
            actor_principal=owner,
        )


async def test_bind_scope_reference_rejects_soft_deleted(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "org-manager", {"org:manage"}, actor_id=owner.user_id, actor_principal=owner
    )
    member = await _member(control_session_factory, tenant_id)
    deleted_org = await _org(control_session_factory, tenant_id, deleted=True)
    with pytest.raises(InvalidReference, match="org scope is deleted"):
        await control.bind_role(
            tenant_id,
            role.id,
            principal_type="user",
            principal_id=member.user_id,
            scope_type="org",
            scope_id=deleted_org,
            actor_id=owner.user_id,
            actor_principal=owner,
        )


async def test_binding_requires_active_membership_and_same_tenant(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "reader", {"resource:read"}, actor_id=owner.user_id, actor_principal=owner
    )
    stranger = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    async with control_session_factory() as session:
        session.add(User(id=stranger.user_id, status="active"))
        await session.commit()
    with pytest.raises(CrossTenantReferenceError):
        await control.bind_role(
            tenant_id,
            role.id,
            principal_type="user",
            principal_id=stranger.user_id,
            scope_type="tenant",
            scope_id=None,
            actor_id=owner.user_id,
            actor_principal=owner,
        )


async def test_bind_rejects_membership_in_another_tenant(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    other_tenant = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "reader", {"resource:read"}, actor_id=owner.user_id, actor_principal=owner
    )
    member = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    async with control_session_factory() as session:
        session.add(User(id=member.user_id, status="active"))
        await session.flush()
        session.add(
            Membership(
                tenant_id=other_tenant, id=uuid.uuid4(), user_id=member.user_id, status="active"
            )
        )
        await session.commit()
    with pytest.raises(CrossTenantReferenceError):
        await control.bind_role(
            tenant_id,
            role.id,
            principal_type="user",
            principal_id=member.user_id,
            scope_type="tenant",
            scope_id=None,
            actor_id=owner.user_id,
            actor_principal=owner,
        )


async def test_bind_service_account_principal(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "bot-reader", {"resource:read"}, actor_id=owner.user_id, actor_principal=owner
    )
    account_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            ServiceAccount(
                tenant_id=tenant_id,
                id=account_id,
                name=f"bot-{account_id.hex[:6]}",
                status="active",
            )
        )
        await session.commit()
    binding = await control.bind_role(
        tenant_id,
        role.id,
        principal_type="service_account",
        principal_id=account_id,
        scope_type="tenant",
        scope_id=None,
        actor_id=owner.user_id,
        actor_principal=owner,
    )
    assert binding.principal_type == "service_account"
    assert binding.principal_id == account_id


async def test_bind_rejects_inactive_service_account(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "bot-reader", {"resource:read"}, actor_id=owner.user_id, actor_principal=owner
    )
    account_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            ServiceAccount(
                tenant_id=tenant_id,
                id=account_id,
                name=f"bot-{account_id.hex[:6]}",
                status="suspended",
            )
        )
        await session.commit()
    with pytest.raises(CrossTenantReferenceError):
        await control.bind_role(
            tenant_id,
            role.id,
            principal_type="service_account",
            principal_id=account_id,
            scope_type="tenant",
            scope_id=None,
            actor_id=owner.user_id,
            actor_principal=owner,
        )


async def test_bind_and_unbind_roundtrip(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    audit = RecordingPlatformAudit()
    control = _access(control_session_factory, audit=audit)
    role = await control.create_role(
        tenant_id, "member", {"resource:read"}, actor_id=owner.user_id, actor_principal=owner
    )
    member = await _member(control_session_factory, tenant_id)
    binding = await control.bind_role(
        tenant_id,
        role.id,
        principal_type="user",
        principal_id=member.user_id,
        scope_type="tenant",
        scope_id=None,
        actor_id=owner.user_id,
        actor_principal=owner,
    )
    assert binding.scope_type == "tenant"
    created = audit.entries[-1]
    assert created["action"] == "binding.created"
    assert created["tenant_id"] == tenant_id
    assert created["actor_id"] == owner.user_id
    assert created["metadata"] == {
        "role_id": str(role.id),
        "principal_id": str(member.user_id),
        "scope": "tenant:None",
    }
    await control.unbind_role(tenant_id, binding.id, actor_id=owner.user_id, actor_principal=owner)
    removed = audit.entries[-1]
    assert removed["action"] == "binding.removed"
    assert removed["tenant_id"] == tenant_id
    assert removed["actor_id"] == owner.user_id
    assert removed["metadata"] == {"binding_id": str(binding.id)}
    async with control_session_factory() as session:
        remaining = (
            await session.execute(sa.select(RoleBinding).where(RoleBinding.id == binding.id))
        ).scalar_one_or_none()
    assert remaining is None


async def test_binding_requires_holding_the_role_permissions(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "manager", {"tenant:manage"}, actor_id=owner.user_id, actor_principal=owner
    )
    weak, _, _ = await _seed_actor(
        control_session_factory,
        tenant_id,
        name=f"weak-{uuid.uuid4().hex[:6]}",
        codes={"role:manage", "resource:read"},
    )
    member = await _member(control_session_factory, tenant_id)
    with pytest.raises(RoleEscalationBlocked):
        await control.bind_role(
            tenant_id,
            role.id,
            principal_type="user",
            principal_id=member.user_id,
            scope_type="tenant",
            scope_id=None,
            actor_id=weak.user_id,
            actor_principal=weak,
        )


async def test_owner_role_assignment_requires_full_catalog(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    full, _, _ = await _full_actor(
        control_session_factory, tenant_id, name=f"full-{uuid.uuid4().hex[:6]}"
    )
    partial, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    owner_role = await control.create_role(
        tenant_id, "owner", {"resource:read"}, actor_id=full.user_id, actor_principal=full
    )
    member = await _member(control_session_factory, tenant_id)
    with pytest.raises(AuthorizationError):
        await control.bind_role(
            tenant_id,
            owner_role.id,
            principal_type="user",
            principal_id=member.user_id,
            scope_type="tenant",
            scope_id=None,
            actor_id=partial.user_id,
            actor_principal=partial,
        )
    binding = await control.bind_role(
        tenant_id,
        owner_role.id,
        principal_type="user",
        principal_id=member.user_id,
        scope_type="tenant",
        scope_id=None,
        actor_id=full.user_id,
        actor_principal=full,
    )
    assert binding.role_id == owner_role.id


async def test_unbind_refuses_to_remove_last_owner(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, role_id, binding_id = await _full_actor(control_session_factory, tenant_id, name="owner")
    control = _access(control_session_factory)
    with pytest.raises(AuthorizationError, match="cannot remove the last owner"):
        await control.unbind_role(
            tenant_id, binding_id, actor_id=owner.user_id, actor_principal=owner
        )
    second = await _member(control_session_factory, tenant_id)
    second_binding = await control.bind_role(
        tenant_id,
        role_id,
        principal_type="user",
        principal_id=second.user_id,
        scope_type="tenant",
        scope_id=None,
        actor_id=owner.user_id,
        actor_principal=owner,
    )
    await control.unbind_role(
        tenant_id, second_binding.id, actor_id=owner.user_id, actor_principal=owner
    )
    with pytest.raises(AuthorizationError, match="cannot remove the last owner"):
        await control.unbind_role(
            tenant_id, binding_id, actor_id=owner.user_id, actor_principal=owner
        )


async def test_unbind_takes_tenant_lock_before_counting(control_session_factory, monkeypatch):
    tenant_id = await _tenant(control_session_factory)
    owner, role_id, first_binding = await _full_actor(
        control_session_factory, tenant_id, name="owner"
    )
    control = _access(control_session_factory)
    second = await _member(control_session_factory, tenant_id)
    second_binding = await control.bind_role(
        tenant_id,
        role_id,
        principal_type="user",
        principal_id=second.user_id,
        scope_type="tenant",
        scope_id=None,
        actor_id=owner.user_id,
        actor_principal=owner,
    )
    original_lock = control._lock
    locked: list[uuid.UUID] = []

    async def racing_lock(session, locked_tenant_id):
        locked.append(locked_tenant_id)
        async with control_session_factory() as raw:
            await raw.execute(sa.delete(RoleBinding).where(RoleBinding.id == second_binding.id))
            await raw.commit()
        await original_lock(session, locked_tenant_id)

    monkeypatch.setattr(control, "_lock", racing_lock)
    with pytest.raises(AuthorizationError, match="cannot remove the last owner"):
        await control.unbind_role(
            tenant_id, first_binding, actor_id=owner.user_id, actor_principal=owner
        )
    assert locked == [tenant_id]
