import uuid
from datetime import timedelta

import pytest
import sqlalchemy as sa

from jdlib.authz.access import AccessControl, ScopeLookup
from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.context import Principal, PrincipalKind
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.models import (
    Invitation,
    Membership,
    Role,
    RoleBinding,
    RolePermission,
    Tenant,
    User,
)
from jdlib.errors import AuthorizationError, CrossTenantReferenceError, InvalidReference
from tests.integration.test_access_bindings import _org, _TenantScopeLookup


def _access(
    control_session_factory,
    *,
    audit: RecordingPlatformAudit | None = None,
    scope_lookup: ScopeLookup | None = None,
) -> AccessControl:
    return AccessControl(
        session_factory=control_session_factory,
        catalog=PermissionCatalog.with_builtins(),
        reader=ControlAccessReader(control_session_factory),
        cache=AuthzCache(),
        audit=audit or RecordingPlatformAudit(),
        scope_lookup=scope_lookup,
    )


async def _tenant(control_session_factory) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"inv-{tenant_id.hex[:8]}", name="INV", status="active")
        )
        await session.commit()
    return tenant_id


async def _role(
    control_session_factory, tenant_id: uuid.UUID, *, permission: str = "resource:read"
) -> uuid.UUID:
    role_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(Role(tenant_id=tenant_id, id=role_id, name=f"member-{role_id.hex[:6]}"))
        session.add(
            RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code=permission)
        )
        await session.commit()
    return role_id


async def _user(control_session_factory, *, email: str | None = None) -> uuid.UUID:
    user_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=user_id, email=email, status="active"))
        await session.commit()
    return user_id


async def _invite(
    control: AccessControl,
    tenant_id: uuid.UUID,
    role_id: uuid.UUID,
    *,
    email: str = "new@example.com",
    scope_type: str = "tenant",
    scope_id: uuid.UUID | None = None,
    invited_by: uuid.UUID | None = None,
    ttl: timedelta = timedelta(days=7),
) -> tuple[Invitation, str]:
    return await control.invite(
        tenant_id,
        email=email,
        role_id=role_id,
        scope_type=scope_type,
        scope_id=scope_id,
        invited_by=invited_by,
        ttl=ttl,
    )


async def test_invite_and_accept_creates_membership_and_binding(control_session_factory):
    tenant_id = uuid.uuid4()
    role_id = uuid.uuid4()
    owner = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"inv-{tenant_id.hex[:8]}", name="INV", status="active")
        )
        await session.flush()
        session.add(User(id=owner.user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=role_id, name=f"member-{role_id.hex[:6]}"))
        await session.flush()
        session.add(
            Membership(
                tenant_id=tenant_id, id=uuid.uuid4(), user_id=owner.user_id, status="active"
            )
        )
        session.add(
            RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code="resource:read")
        )
        await session.commit()
    control = _access(control_session_factory)
    invitation, token = await control.invite(
        tenant_id,
        email="new@example.com",
        role_id=role_id,
        scope_type="tenant",
        scope_id=None,
        invited_by=owner.user_id,
    )
    assert invitation.status == "pending"
    invitee_user = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            User(id=invitee_user, email=f"user-{tenant_id.hex[:8]}@example.com", status="active")
        )
        await session.commit()
    membership = await control.accept_invitation(token, user_id=invitee_user)
    assert membership.status == "active"
    async with control_session_factory() as session:
        binding_count = (
            await session.execute(
                sa.select(sa.func.count()).select_from(RoleBinding).where(
                    RoleBinding.tenant_id == tenant_id, RoleBinding.principal_id == invitee_user
                )
            )
        ).scalar_one()
        stored = (
            await session.execute(sa.select(Invitation).where(Invitation.id == invitation.id))
        ).scalar_one()
    assert binding_count == 1
    assert stored.status == "accepted"
    with pytest.raises(InvalidReference):
        await control.accept_invitation(token, user_id=invitee_user)


async def test_invite_rejects_unknown_role(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    control = _access(control_session_factory)
    with pytest.raises(InvalidReference, match="role not found"):
        await _invite(control, tenant_id, uuid.uuid4())


async def test_invitation_stores_argon2id_hash(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    invitation, token = await _invite(control, tenant_id, role_id)
    secret = token.rsplit("_", 1)[1]
    async with control_session_factory() as session:
        stored = (
            await session.execute(sa.select(Invitation).where(Invitation.id == invitation.id))
        ).scalar_one()
    assert stored.token_id == token.split("_")[1]
    assert stored.token_hash.startswith("$argon2id$")
    assert secret not in stored.token_hash


async def test_accept_rejects_tampered_token(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    invitation, _ = await _invite(control, tenant_id, role_id)
    invitee = await _user(control_session_factory)
    with pytest.raises(InvalidReference, match="invalid invitation token"):
        await control.accept_invitation(f"inv_{invitation.token_id}_wrong", user_id=invitee)
    with pytest.raises(InvalidReference, match="invalid invitation token"):
        await control.accept_invitation("not-a-token", user_id=invitee)


async def test_accept_rejects_expired_invitation(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    invitee = await _user(control_session_factory)
    _, token = await _invite(control, tenant_id, role_id, ttl=timedelta(seconds=-1))
    with pytest.raises(InvalidReference, match="expired"):
        await control.accept_invitation(token, user_id=invitee)


async def test_accept_validates_org_scope_reference(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    role_id = await _role(control_session_factory, tenant_id)
    org_id = await _org(control_session_factory, tenant_id)
    control = _access(
        control_session_factory, scope_lookup=_TenantScopeLookup(control_session_factory)
    )
    invitee = await _user(control_session_factory)
    _, token = await _invite(
        control, tenant_id, role_id, scope_type="org", scope_id=org_id
    )
    membership = await control.accept_invitation(token, user_id=invitee)
    assert membership.status == "active"
    async with control_session_factory() as session:
        binding = (
            await session.execute(
                sa.select(RoleBinding).where(
                    RoleBinding.tenant_id == tenant_id,
                    RoleBinding.principal_id == invitee,
                )
            )
        ).scalar_one()
    assert binding.scope_type == "org"
    assert binding.scope_id == org_id


async def test_accept_rejects_missing_org_scope(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(
        control_session_factory, scope_lookup=_TenantScopeLookup(control_session_factory)
    )
    invitee = await _user(control_session_factory)
    _, token = await _invite(
        control, tenant_id, role_id, scope_type="org", scope_id=uuid.uuid4()
    )
    with pytest.raises(InvalidReference, match="org scope not found"):
        await control.accept_invitation(token, user_id=invitee)


async def test_accept_rejects_foreign_org_scope(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    other_tenant = await _tenant(control_session_factory)
    role_id = await _role(control_session_factory, tenant_id)
    foreign_org = await _org(control_session_factory, other_tenant)
    control = _access(
        control_session_factory, scope_lookup=_TenantScopeLookup(control_session_factory)
    )
    invitee = await _user(control_session_factory)
    _, token = await _invite(
        control, tenant_id, role_id, scope_type="org", scope_id=foreign_org
    )
    with pytest.raises(CrossTenantReferenceError):
        await control.accept_invitation(token, user_id=invitee)


async def test_accept_rejects_deleted_org_scope(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    role_id = await _role(control_session_factory, tenant_id)
    deleted_org = await _org(control_session_factory, tenant_id, deleted=True)
    control = _access(
        control_session_factory, scope_lookup=_TenantScopeLookup(control_session_factory)
    )
    invitee = await _user(control_session_factory)
    _, token = await _invite(
        control, tenant_id, role_id, scope_type="org", scope_id=deleted_org
    )
    with pytest.raises(CrossTenantReferenceError):
        await control.accept_invitation(token, user_id=invitee)


async def test_accept_requires_scope_lookup_configured(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    invitee = await _user(control_session_factory)
    _, token = await _invite(
        control, tenant_id, role_id, scope_type="org", scope_id=uuid.uuid4()
    )
    with pytest.raises(AuthorizationError, match="org scope validation is not configured"):
        await control.accept_invitation(token, user_id=invitee)


async def test_invitation_audits_created_and_accepted(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    role_id = await _role(control_session_factory, tenant_id)
    owner_id = await _user(control_session_factory)
    audit = RecordingPlatformAudit()
    control = _access(control_session_factory, audit=audit)
    invitation, token = await _invite(
        control, tenant_id, role_id, email="new@example.com", invited_by=owner_id
    )
    created = audit.entries[-1]
    assert created["action"] == "invitation.created"
    assert created["tenant_id"] == tenant_id
    assert created["actor_id"] == owner_id
    assert created["metadata"] == {"email": "new@example.com", "role_id": str(role_id)}
    invitee = await _user(
        control_session_factory, email=f"invitee-{tenant_id.hex[:8]}@example.com"
    )
    await control.accept_invitation(token, user_id=invitee)
    accepted = audit.entries[-1]
    assert accepted["action"] == "invitation.accepted"
    assert accepted["tenant_id"] == tenant_id
    assert accepted["actor_id"] == invitee
    assert accepted["metadata"] == {"invitation_id": str(invitation.id)}
