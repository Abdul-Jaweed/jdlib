import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa

from jdlib.authz.access import (
    AccessControl,
    ScopeLookup,
    build_invitation_token,
    hash_invitation_secret,
)
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
from jdlib.errors import (
    AuthorizationError,
    CrossTenantReferenceError,
    InvalidReference,
    RoleScopeMismatch,
)
from tests.integration.test_access_bindings import _org, _TenantScopeLookup


def _access(
    control_session_factory,
    *,
    audit: RecordingPlatformAudit | None = None,
    scope_lookup: ScopeLookup | None = None,
    cache: AuthzCache | None = None,
) -> AccessControl:
    return AccessControl(
        session_factory=control_session_factory,
        catalog=PermissionCatalog.with_builtins(),
        reader=ControlAccessReader(control_session_factory),
        cache=cache or AuthzCache(),
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


async def _actor(
    control_session_factory, tenant_id: uuid.UUID, *, permissions: set[str] | None = None
) -> Principal:
    principal = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    role_id = uuid.uuid4()
    codes = {"member:invite"} if permissions is None else permissions
    async with control_session_factory() as session:
        session.add(User(id=principal.user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=role_id, name=f"actor-{role_id.hex[:6]}"))
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
                id=uuid.uuid4(),
                role_id=role_id,
                principal_type="user",
                principal_id=principal.user_id,
                scope_type="tenant",
            )
        )
        await session.commit()
    return principal


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
    actor: Principal,
    *,
    email: str = "new@example.com",
    scope_type: str = "tenant",
    scope_id: uuid.UUID | None = None,
    ttl: timedelta = timedelta(days=7),
) -> tuple[Invitation, str]:
    return await control.invite(
        tenant_id,
        email=email,
        role_id=role_id,
        scope_type=scope_type,
        scope_id=scope_id,
        invited_by=actor.user_id,
        actor_principal=actor,
        ttl=ttl,
    )


async def _seed_invitation(
    control_session_factory,
    tenant_id: uuid.UUID,
    role_id: uuid.UUID,
    *,
    email: str = "new@example.com",
    scope_type: str = "tenant",
    scope_id: uuid.UUID | None = None,
) -> str:
    token = build_invitation_token()
    token_id, secret = token.split("_")[1], token.rsplit("_", 1)[1]
    async with control_session_factory() as session:
        session.add(
            Invitation(
                tenant_id=tenant_id,
                email=email,
                scope_type=scope_type,
                scope_id=scope_id,
                role_id=role_id,
                token_id=token_id,
                token_hash=hash_invitation_secret(secret),
                status="pending",
                expires_at=datetime.now(UTC) + timedelta(days=7),
            )
        )
        await session.commit()
    return token


def _probe(cache: AuthzCache) -> None:
    cache.put("probe", "value")
    assert cache.get("probe") == "value"


async def test_invite_and_accept_creates_membership_and_binding(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    cache = AuthzCache()
    control = _access(control_session_factory, cache=cache)
    _probe(cache)
    invitation, token = await _invite(control, tenant_id, role_id, actor)
    assert cache.get("probe") is None
    assert invitation.status == "pending"
    invitee_user = await _user(
        control_session_factory, email=f"user-{tenant_id.hex[:8]}@example.com"
    )
    accept_cache = AuthzCache()
    accept_control = _access(control_session_factory, cache=accept_cache)
    _probe(accept_cache)
    membership = await accept_control.accept_invitation(token, user_id=invitee_user)
    assert accept_cache.get("probe") is None
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


async def test_invite_requires_member_invite_permission(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id, permissions={"resource:read"})
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    with pytest.raises(AuthorizationError, match="missing permission: member:invite"):
        await _invite(control, tenant_id, role_id, actor)


async def test_invite_rejects_unknown_role(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    with pytest.raises(InvalidReference, match="role not found"):
        await _invite(control, tenant_id, uuid.uuid4(), actor)


async def test_invite_rejects_scope_shape(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    with pytest.raises(InvalidReference, match="tenant scope must not carry a scope id"):
        await _invite(control, tenant_id, role_id, actor, scope_id=uuid.uuid4())
    with pytest.raises(InvalidReference, match="team scope requires a scope id"):
        await _invite(control, tenant_id, role_id, actor, scope_type="team")
    with pytest.raises(InvalidReference, match="unsupported scope type"):
        await _invite(
            control, tenant_id, role_id, actor, scope_type="orgy", scope_id=uuid.uuid4()
        )


async def test_invite_requires_scope_lookup_configured(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    with pytest.raises(AuthorizationError, match="org scope validation is not configured"):
        await _invite(
            control, tenant_id, role_id, actor, scope_type="org", scope_id=uuid.uuid4()
        )


async def test_invite_validates_org_scope_reference(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    other_tenant = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    foreign_org = await _org(control_session_factory, other_tenant)
    deleted_org = await _org(control_session_factory, tenant_id, deleted=True)
    control = _access(
        control_session_factory, scope_lookup=_TenantScopeLookup(control_session_factory)
    )
    with pytest.raises(InvalidReference, match="org scope not found"):
        await _invite(
            control, tenant_id, role_id, actor, scope_type="org", scope_id=uuid.uuid4()
        )
    with pytest.raises(CrossTenantReferenceError):
        await _invite(
            control, tenant_id, role_id, actor, scope_type="org", scope_id=foreign_org
        )
    with pytest.raises(CrossTenantReferenceError):
        await _invite(
            control, tenant_id, role_id, actor, scope_type="org", scope_id=deleted_org
        )


async def test_invite_rejects_role_scope_mismatch(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id, permission="tenant:manage")
    org_id = await _org(control_session_factory, tenant_id)
    control = _access(
        control_session_factory, scope_lookup=_TenantScopeLookup(control_session_factory)
    )
    with pytest.raises(RoleScopeMismatch, match="cannot be bound at org scope"):
        await _invite(control, tenant_id, role_id, actor, scope_type="org", scope_id=org_id)


async def test_accept_rechecks_role_scope_compatibility(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    org_id = await _org(control_session_factory, tenant_id)
    control = _access(
        control_session_factory, scope_lookup=_TenantScopeLookup(control_session_factory)
    )
    invitation, token = await _invite(
        control, tenant_id, role_id, actor, scope_type="org", scope_id=org_id
    )
    async with control_session_factory() as session:
        await session.execute(
            sa.update(RolePermission)
            .where(
                RolePermission.tenant_id == tenant_id, RolePermission.role_id == role_id
            )
            .values(permission_code="tenant:manage")
        )
        await session.commit()
    invitee = await _user(control_session_factory)
    with pytest.raises(RoleScopeMismatch, match="cannot be bound at org scope"):
        await control.accept_invitation(token, user_id=invitee)
    async with control_session_factory() as session:
        stored = (
            await session.execute(sa.select(Invitation).where(Invitation.id == invitation.id))
        ).scalar_one()
        memberships = (
            await session.execute(
                sa.select(sa.func.count()).select_from(Membership).where(
                    Membership.tenant_id == tenant_id, Membership.user_id == invitee
                )
            )
        ).scalar_one()
    assert stored.status == "pending"
    assert memberships == 0


async def test_reinvite_revokes_the_prior_pending_invitation(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    first_role = await _role(control_session_factory, tenant_id)
    second_role = await _role(control_session_factory, tenant_id, permission="resource:update")
    control = _access(control_session_factory)
    first, first_token = await _invite(control, tenant_id, first_role, actor)
    second, second_token = await _invite(control, tenant_id, second_role, actor)
    assert second.status == "pending"
    async with control_session_factory() as session:
        stored_first = (
            await session.execute(sa.select(Invitation).where(Invitation.id == first.id))
        ).scalar_one()
        pending = (
            await session.execute(
                sa.select(sa.func.count()).select_from(Invitation).where(
                    Invitation.tenant_id == tenant_id, Invitation.status == "pending"
                )
            )
        ).scalar_one()
    assert stored_first.status == "revoked"
    assert stored_first.revoked_at is not None
    assert pending == 1
    invitee = await _user(control_session_factory)
    with pytest.raises(InvalidReference, match="invitation is revoked"):
        await control.accept_invitation(first_token, user_id=invitee)
    membership = await control.accept_invitation(second_token, user_id=invitee)
    assert membership.status == "active"
    async with control_session_factory() as session:
        bindings = (
            await session.execute(
                sa.select(RoleBinding).where(
                    RoleBinding.tenant_id == tenant_id, RoleBinding.principal_id == invitee
                )
            )
        ).scalars().all()
    assert len(bindings) == 1
    assert bindings[0].role_id == second_role


async def test_accept_reuses_existing_membership_and_binding(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    invitee = await _user(control_session_factory)
    membership_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Membership(
                tenant_id=tenant_id, id=membership_id, user_id=invitee, status="active"
            )
        )
        await session.flush()
        session.add(
            RoleBinding(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                role_id=role_id,
                principal_type="user",
                principal_id=invitee,
                scope_type="tenant",
            )
        )
        await session.commit()
    control = _access(control_session_factory)
    _, token = await _invite(control, tenant_id, role_id, actor)
    returned = await control.accept_invitation(token, user_id=invitee)
    assert returned.id == membership_id
    second_role = await _role(control_session_factory, tenant_id, permission="resource:update")
    _, second_token = await _invite(control, tenant_id, second_role, actor)
    await control.accept_invitation(second_token, user_id=invitee)
    async with control_session_factory() as session:
        membership_count = (
            await session.execute(
                sa.select(sa.func.count()).select_from(Membership).where(
                    Membership.tenant_id == tenant_id, Membership.user_id == invitee
                )
            )
        ).scalar_one()
        bindings = (
            await session.execute(
                sa.select(RoleBinding.role_id).where(
                    RoleBinding.tenant_id == tenant_id, RoleBinding.principal_id == invitee
                )
            )
        ).scalars().all()
    assert membership_count == 1
    assert sorted(bindings) == sorted([role_id, second_role])


async def test_accept_rejects_suspended_membership(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    invitee = await _user(control_session_factory)
    async with control_session_factory() as session:
        session.add(
            Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=invitee, status="suspended")
        )
        await session.commit()
    control = _access(control_session_factory)
    _, token = await _invite(control, tenant_id, role_id, actor)
    with pytest.raises(InvalidReference, match="membership is suspended"):
        await control.accept_invitation(token, user_id=invitee)
    async with control_session_factory() as session:
        bindings = (
            await session.execute(
                sa.select(sa.func.count()).select_from(RoleBinding).where(
                    RoleBinding.tenant_id == tenant_id, RoleBinding.principal_id == invitee
                )
            )
        ).scalar_one()
    assert bindings == 0


async def test_accept_rejects_tampered_token(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    invitation, _ = await _invite(control, tenant_id, role_id, actor)
    invitee = await _user(control_session_factory)
    with pytest.raises(InvalidReference, match="invalid invitation token"):
        await control.accept_invitation(f"inv_{invitation.token_id}_wrong", user_id=invitee)
    with pytest.raises(InvalidReference, match="invalid invitation token"):
        await control.accept_invitation("not-a-token", user_id=invitee)


async def test_accept_rejects_expired_invitation(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    invitee = await _user(control_session_factory)
    _, token = await _invite(
        control, tenant_id, role_id, actor, ttl=timedelta(seconds=-1)
    )
    with pytest.raises(InvalidReference, match="expired"):
        await control.accept_invitation(token, user_id=invitee)


async def test_accept_validates_org_scope_reference(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    org_id = await _org(control_session_factory, tenant_id)
    control = _access(
        control_session_factory, scope_lookup=_TenantScopeLookup(control_session_factory)
    )
    invitee = await _user(control_session_factory)
    _, token = await _invite(control, tenant_id, role_id, actor, scope_type="org", scope_id=org_id)
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
    token = await _seed_invitation(
        control_session_factory, tenant_id, role_id, scope_type="org", scope_id=uuid.uuid4()
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
    token = await _seed_invitation(
        control_session_factory, tenant_id, role_id, scope_type="org", scope_id=foreign_org
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
    token = await _seed_invitation(
        control_session_factory, tenant_id, role_id, scope_type="org", scope_id=deleted_org
    )
    with pytest.raises(CrossTenantReferenceError):
        await control.accept_invitation(token, user_id=invitee)


async def test_accept_requires_scope_lookup_configured(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    invitee = await _user(control_session_factory)
    token = await _seed_invitation(
        control_session_factory, tenant_id, role_id, scope_type="org", scope_id=uuid.uuid4()
    )
    with pytest.raises(AuthorizationError, match="org scope validation is not configured"):
        await control.accept_invitation(token, user_id=invitee)


async def test_invitation_stores_argon2id_hash(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    control = _access(control_session_factory)
    invitation, token = await _invite(control, tenant_id, role_id, actor)
    secret = token.rsplit("_", 1)[1]
    async with control_session_factory() as session:
        stored = (
            await session.execute(sa.select(Invitation).where(Invitation.id == invitation.id))
        ).scalar_one()
    assert stored.token_id == token.split("_")[1]
    assert stored.token_hash.startswith("$argon2id$")
    assert secret not in stored.token_hash


async def test_invitation_audits_created_and_accepted(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _actor(control_session_factory, tenant_id)
    role_id = await _role(control_session_factory, tenant_id)
    audit = RecordingPlatformAudit()
    control = _access(control_session_factory, audit=audit)
    invitation, token = await _invite(
        control, tenant_id, role_id, actor, email="new@example.com"
    )
    created = audit.entries[-1]
    assert created["action"] == "invitation.created"
    assert created["tenant_id"] == tenant_id
    assert created["actor_id"] == actor.user_id
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
