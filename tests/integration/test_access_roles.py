import uuid
from datetime import UTC, datetime

import pytest

from jdlib.authz.access import AccessControl
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
    ServiceAccount,
    Tenant,
    User,
)
from jdlib.errors import AuthorizationError, RoleEscalationBlocked, UnknownPermission


def _principal(role: str) -> Principal:
    user_id = uuid.uuid4()
    return Principal(kind=PrincipalKind.USER, id=user_id, user_id=user_id)


async def _tenant(control_session_factory) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"ac-{tenant_id.hex[:8]}", name="AC", status="active")
        )
        await session.commit()
    return tenant_id


async def _seed_actor(control_session_factory, tenant_id: uuid.UUID, permissions: set[str]):
    actor = _principal("owner")
    role_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=actor.user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=role_id, name=f"owner-{role_id.hex[:6]}"))
        await session.flush()
        session.add(
            Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=actor.user_id, status="active")
        )
        for code in permissions:
            session.add(
                RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code=code)
            )
        session.add(
            RoleBinding(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                role_id=role_id,
                principal_type="user",
                principal_id=actor.user_id,
                scope_type="tenant",
            )
        )
        await session.commit()
    return actor


async def _seed_service_account_actor(
    control_session_factory, tenant_id: uuid.UUID, permissions: set[str], scopes: set[str]
) -> Principal:
    account_id = uuid.uuid4()
    role_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            ServiceAccount(
                tenant_id=tenant_id,
                id=account_id,
                name=f"bot-{account_id.hex[:6]}",
                status="active",
            )
        )
        session.add(Role(tenant_id=tenant_id, id=role_id, name=f"sa-{role_id.hex[:6]}"))
        await session.flush()
        for code in permissions:
            session.add(
                RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code=code)
            )
        session.add(
            RoleBinding(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                role_id=role_id,
                principal_type="service_account",
                principal_id=account_id,
                scope_type="tenant",
            )
        )
        await session.commit()
    return Principal(
        kind=PrincipalKind.SERVICE_ACCOUNT,
        id=account_id,
        tenant_id=tenant_id,
        scopes=frozenset(scopes),
    )


def _access(control_session_factory, catalog=None) -> tuple[AccessControl, RecordingPlatformAudit]:
    audit = RecordingPlatformAudit()
    cache = AuthzCache()
    control = AccessControl(
        session_factory=control_session_factory,
        catalog=catalog or PermissionCatalog.with_builtins(),
        reader=ControlAccessReader(control_session_factory),
        cache=cache,
        audit=audit,
    )
    return control, audit


async def test_create_role_requires_holding_every_permission(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(control_session_factory, tenant_id, {"resource:read"})
    control, audit = _access(control_session_factory)
    role = await control.create_role(
        tenant_id,
        "reader",
        {"resource:read"},
        actor_id=actor.user_id,
        actor_principal=actor,
    )
    assert role.name == "reader"
    assert audit.entries[-1]["action"] == "role.created"
    with pytest.raises(RoleEscalationBlocked):
        await control.create_role(
            tenant_id,
            "escalated",
            {"resource:read", "tenant:manage"},
            actor_id=actor.user_id,
            actor_principal=actor,
        )


async def test_create_role_rejects_unknown_permission(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(control_session_factory, tenant_id, {"resource:read"})
    control, _ = _access(control_session_factory)
    with pytest.raises(UnknownPermission):
        await control.create_role(
            tenant_id, "bad", {"mystery:do"}, actor_id=actor.user_id, actor_principal=actor
        )


async def test_update_role_revalidates_subset_and_invalidates_cache(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(
        control_session_factory, tenant_id, {"resource:read", "resource:update"}
    )
    control, _ = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "editor", {"resource:read"}, actor_id=actor.user_id, actor_principal=actor
    )
    updated = await control.update_role(
        tenant_id,
        role.id,
        {"resource:read", "resource:update"},
        actor_id=actor.user_id,
        actor_principal=actor,
    )
    assert updated.id == role.id
    with pytest.raises(AuthorizationError):
        await control.update_role(
            tenant_id,
            role.id,
            {"tenant:manage"},
            actor_id=actor.user_id,
            actor_principal=actor,
        )


async def test_delete_role_blocked_while_bindings_exist(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(control_session_factory, tenant_id, {"resource:read"})
    control, _ = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "temp", {"resource:read"}, actor_id=actor.user_id, actor_principal=actor
    )
    member = _principal("member")
    async with control_session_factory() as session:
        session.add(User(id=member.user_id, status="active"))
        await session.flush()
        session.add(
            Membership(
                tenant_id=tenant_id, id=uuid.uuid4(), user_id=member.user_id, status="active"
            )
        )
        await session.commit()
    await control.bind_role(
        tenant_id,
        role.id,
        principal_type="user",
        principal_id=member.user_id,
        scope_type="tenant",
        scope_id=None,
        actor_id=actor.user_id,
        actor_principal=actor,
    )
    with pytest.raises(AuthorizationError):
        await control.delete_role(tenant_id, role.id, actor_id=actor.user_id, actor_principal=actor)


async def test_system_roles_are_immutable(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(control_session_factory, tenant_id, {"resource:read"})
    control, _ = _access(control_session_factory)
    role = await control.create_role(
        tenant_id,
        "builtin",
        {"resource:read"},
        actor_id=actor.user_id,
        actor_principal=actor,
        is_system=True,
    )
    with pytest.raises(AuthorizationError):
        await control.update_role(
            tenant_id, role.id, {"resource:read"}, actor_id=actor.user_id, actor_principal=actor
        )
    with pytest.raises(AuthorizationError):
        await control.delete_role(tenant_id, role.id, actor_id=actor.user_id, actor_principal=actor)


async def test_scoped_service_account_permissions_are_narrowed(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_service_account_actor(
        control_session_factory,
        tenant_id,
        {"resource:read", "resource:update"},
        {"resource:read"},
    )
    control, _ = _access(control_session_factory)
    assert await control.actor_permissions(tenant_id, actor) == frozenset({"resource:read"})


async def test_scoped_service_account_cannot_create_role_outside_scopes(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_service_account_actor(
        control_session_factory,
        tenant_id,
        {"resource:read", "resource:update"},
        {"resource:read"},
    )
    control, _ = _access(control_session_factory)
    with pytest.raises(RoleEscalationBlocked):
        await control.create_role(
            tenant_id,
            "outside-scope",
            {"resource:update"},
            actor_id=actor.id,
            actor_principal=actor,
        )


async def test_scoped_service_account_cannot_bind_role_outside_scopes(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_service_account_actor(
        control_session_factory,
        tenant_id,
        {"resource:read", "resource:update"},
        {"resource:read"},
    )
    control, _ = _access(control_session_factory)
    target_role_id = uuid.uuid4()
    member = _principal("member")
    async with control_session_factory() as session:
        session.add(User(id=member.user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=target_role_id, name="updater"))
        await session.flush()
        session.add(
            Membership(
                tenant_id=tenant_id, id=uuid.uuid4(), user_id=member.user_id, status="active"
            )
        )
        session.add(
            RolePermission(
                tenant_id=tenant_id, role_id=target_role_id, permission_code="resource:update"
            )
        )
        await session.commit()
    with pytest.raises(RoleEscalationBlocked):
        await control.bind_role(
            tenant_id,
            target_role_id,
            principal_type="user",
            principal_id=member.user_id,
            scope_type="tenant",
            scope_id=None,
            actor_id=actor.id,
            actor_principal=actor,
        )


async def test_update_role_audits_permission_diff(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(
        control_session_factory, tenant_id, {"resource:read", "resource:update"}
    )
    control, audit = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "diff", {"resource:read"}, actor_id=actor.user_id, actor_principal=actor
    )
    await control.update_role(
        tenant_id,
        role.id,
        {"resource:update"},
        actor_id=actor.user_id,
        actor_principal=actor,
    )
    entry = audit.entries[-1]
    assert entry["action"] == "role.permissions_changed"
    metadata = entry["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["added"] == ["resource:update"]
    assert metadata["removed"] == ["resource:read"]


async def test_delete_role_blocked_by_terminal_invitation(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    actor = await _seed_actor(control_session_factory, tenant_id, {"resource:read"})
    control, _ = _access(control_session_factory)
    role = await control.create_role(
        tenant_id, "invited", {"resource:read"}, actor_id=actor.user_id, actor_principal=actor
    )
    async with control_session_factory() as session:
        session.add(
            Invitation(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                email="accepted@example.com",
                scope_type="tenant",
                role_id=role.id,
                token_id=f"tok-{uuid.uuid4().hex}",
                token_hash="hash",
                status="accepted",
                expires_at=datetime.now(UTC),
            )
        )
        await session.commit()
    with pytest.raises(AuthorizationError):
        await control.delete_role(tenant_id, role.id, actor_id=actor.user_id, actor_principal=actor)
