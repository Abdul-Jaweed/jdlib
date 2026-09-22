import uuid

import pytest
import sqlalchemy as sa

from jdlib.authz.access import AccessControl
from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.context import Principal, PrincipalKind
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.models import (
    Membership,
    Role,
    RoleBinding,
    RolePermission,
    Tenant,
    User,
)
from jdlib.errors import AuthorizationError, CrossTenantReferenceError, RoleScopeMismatch

OWNER_CODES = {
    "tenant:manage",
    "member:manage",
    "role:manage",
    "org:manage",
    "team:manage",
    "resource:read",
    "resource:share",
}


def _access(control_session_factory) -> AccessControl:
    return AccessControl(
        session_factory=control_session_factory,
        catalog=PermissionCatalog.with_builtins(),
        reader=ControlAccessReader(control_session_factory),
        cache=AuthzCache(),
        audit=RecordingPlatformAudit(),
    )


async def _tenant(control_session_factory) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"bd-{tenant_id.hex[:8]}", name="BD", status="active")
        )
        await session.commit()
    return tenant_id


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
    with pytest.raises(RoleScopeMismatch):
        await control.bind_role(
            tenant_id,
            role.id,
            principal_type="user",
            principal_id=member.user_id,
            scope_type="team",
            scope_id=uuid.uuid4(),
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


async def test_bind_and_unbind_roundtrip(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner, _ = await _owner(control_session_factory, tenant_id)
    control = _access(control_session_factory)
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
    await control.unbind_role(tenant_id, binding.id, actor_id=owner.user_id, actor_principal=owner)
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
    with pytest.raises(AuthorizationError):
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
