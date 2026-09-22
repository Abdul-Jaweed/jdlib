import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any, cast

import pytest
import sqlalchemy as sa

from jdlib.authz.access import AccessControl, ResourceRecord
from jdlib.authz.cache import AuthzCache
from jdlib.authz.permissions import Permission, PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.authz.resource_types import ResourceTypeDefinition, ResourceTypeRegistry
from jdlib.context import PlacementStrategy, Principal, PrincipalKind, TenantContext
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.enums import ScopeType
from jdlib.control.models import (
    Membership,
    ResourceGrant,
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
    InvalidResourcePermission,
    RoleEscalationBlocked,
)
from jdlib.models.org import Organization, Team
from jdlib.persistence.session import TenantSession
from tests.support.invoice import Invoice

OWNER_PERMISSIONS = frozenset({"resource:read", "resource:share", "invoice:approve"})
TENANT_SCHEMA = "jt_test"


def _tenant_context(tenant_id: uuid.UUID) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug="gr",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
    )


async def _tenant_session(session_factory, tenant_id: uuid.UUID) -> TenantSession:
    raw = session_factory()
    await raw.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
    return TenantSession(raw, _tenant_context(tenant_id))


class _TenantResourceLookup:
    """Test ResourceLookup backed by a TenantSession (I11/L14)."""

    def __init__(self, session_factory, registry: ResourceTypeRegistry) -> None:
        self._session_factory = session_factory
        self._registry = registry

    async def __call__(
        self, tenant_id: uuid.UUID, resource_type: str, resource_id: uuid.UUID
    ) -> ResourceRecord | None:
        model = cast(Any, self._registry.get(resource_type).model)
        async with await _tenant_session(self._session_factory, tenant_id) as session:
            row = await session.get(model, resource_id)
            if row is not None:
                return ResourceRecord(
                    tenant_id=row.tenant_id,
                    deleted=getattr(row, "deleted_at", None) is not None,
                )
        raw = self._session_factory()
        try:
            await raw.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
            owner = (
                await raw.execute(sa.select(model.tenant_id).where(model.id == resource_id))
            ).scalar_one_or_none()
        finally:
            await raw.close()
        if owner is None:
            return None
        return ResourceRecord(tenant_id=owner, deleted=False)


def _access(
    control_session_factory, *, resource_lookup: bool = True
) -> tuple[AccessControl, RecordingPlatformAudit]:
    catalog = PermissionCatalog.with_builtins()
    catalog.register(
        Permission("invoice:approve", "invoice", frozenset(ScopeType), "Approve")
    )
    catalog.register(Permission("invoice:delete", "invoice", frozenset(ScopeType), "Delete"))
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
    audit = RecordingPlatformAudit()
    control = AccessControl(
        session_factory=control_session_factory,
        catalog=catalog,
        reader=ControlAccessReader(control_session_factory),
        cache=AuthzCache(),
        audit=audit,
        registry=registry,
        resource_lookup=(
            _TenantResourceLookup(control_session_factory, registry) if resource_lookup else None
        ),
    )
    return control, audit


async def _tenant(control_session_factory) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"gr-{tenant_id.hex[:8]}", name="GR", status="active")
        )
        await session.commit()
    return tenant_id


async def _owner_with_grant_permissions(
    control_session_factory,
    tenant_id: uuid.UUID,
    permissions: frozenset[str] = OWNER_PERMISSIONS,
) -> Principal:
    owner = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    role_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=owner.user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=role_id, name=f"owner-{role_id.hex[:6]}"))
        await session.flush()
        session.add(
            Membership(
                tenant_id=tenant_id, id=uuid.uuid4(), user_id=owner.user_id, status="active"
            )
        )
        for code in sorted(permissions):
            session.add(
                RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code=code)
            )
        session.add(
            RoleBinding(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                role_id=role_id,
                principal_type="user",
                principal_id=owner.user_id,
                scope_type="tenant",
            )
        )
        await session.commit()
    return owner


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


async def _invoice(
    control_session_factory,
    tenant_id: uuid.UUID,
    *,
    deleted: bool = False,
    organization_id: uuid.UUID | None = None,
    team_id: uuid.UUID | None = None,
) -> uuid.UUID:
    invoice_id = uuid.uuid4()
    async with await _tenant_session(control_session_factory, tenant_id) as session:
        await session.add(
            Invoice(
                id=invoice_id,
                number=f"INV-{invoice_id.hex[:6]}",
                organization_id=organization_id,
                team_id=team_id,
                deleted_at=datetime.now(UTC) if deleted else None,
            )
        )
        await session.commit()
    return invoice_id


async def _grant(
    control: AccessControl,
    tenant_id: uuid.UUID,
    owner: Principal,
    *,
    resource_id: uuid.UUID,
    principal_id: uuid.UUID,
) -> ResourceGrant:
    return await control.grant_resource(
        tenant_id,
        resource_type="invoice",
        resource_id=resource_id,
        principal_type="user",
        principal_id=principal_id,
        permission="invoice:approve",
        actor_id=owner.user_id,
        actor_principal=owner,
    )


async def _grant_exists(
    control_session_factory, tenant_id: uuid.UUID, resource_id: uuid.UUID
) -> bool:
    async with control_session_factory() as session:
        count = (
            await session.execute(
                sa.select(sa.func.count())
                .select_from(ResourceGrant)
                .where(
                    ResourceGrant.tenant_id == tenant_id,
                    ResourceGrant.resource_type == "invoice",
                    ResourceGrant.resource_id == resource_id,
                )
            )
        ).scalar_one()
    return bool(count)


async def _wait_for_lock_wait(control_session_factory, attempts: int = 100) -> bool:
    for _ in range(attempts):
        await asyncio.sleep(0.05)
        async with control_session_factory() as probe:
            waiting = (
                await probe.execute(
                    sa.text(
                        "SELECT count(*) FROM pg_stat_activity "
                        "WHERE datname = current_database() "
                        "AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()"
                    )
                )
            ).scalar_one()
        if waiting:
            return True
    return False


async def test_grant_requires_namespace_and_holding_permission(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, _ = _access(control_session_factory)
    member = await _member(control_session_factory, tenant_id)
    resource_id = await _invoice(control_session_factory, tenant_id)
    grant = await _grant(
        control, tenant_id, owner, resource_id=resource_id, principal_id=member.user_id
    )
    assert grant.permission_code == "invoice:approve"
    with pytest.raises(InvalidResourcePermission):
        await control.grant_resource(
            tenant_id,
            resource_type="invoice",
            resource_id=resource_id,
            principal_type="user",
            principal_id=member.user_id,
            permission="resource:read",
            actor_id=owner.user_id,
            actor_principal=owner,
        )
    with pytest.raises(RoleEscalationBlocked, match="invoice:delete"):
        await control.grant_resource(
            tenant_id,
            resource_type="invoice",
            resource_id=resource_id,
            principal_type="user",
            principal_id=member.user_id,
            permission="invoice:delete",
            actor_id=owner.user_id,
            actor_principal=owner,
        )


async def test_grant_requires_resource_share(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(
        control_session_factory, tenant_id, frozenset({"invoice:approve"})
    )
    control, _ = _access(control_session_factory)
    member = await _member(control_session_factory, tenant_id)
    resource_id = await _invoice(control_session_factory, tenant_id)
    with pytest.raises(RoleEscalationBlocked, match="resource:share"):
        await _grant(
            control, tenant_id, owner, resource_id=resource_id, principal_id=member.user_id
        )


async def test_grant_rejects_missing_resource(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, _ = _access(control_session_factory)
    member = await _member(control_session_factory, tenant_id)
    with pytest.raises(InvalidReference, match="resource not found"):
        await _grant(
            control,
            tenant_id,
            owner,
            resource_id=uuid.uuid4(),
            principal_id=member.user_id,
        )


async def test_grant_rejects_other_tenant_resource(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    other_tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, _ = _access(control_session_factory)
    member = await _member(control_session_factory, tenant_id)
    foreign_invoice = await _invoice(control_session_factory, other_tenant_id)
    with pytest.raises(CrossTenantReferenceError):
        await _grant(
            control, tenant_id, owner, resource_id=foreign_invoice, principal_id=member.user_id
        )


async def test_grant_rejects_soft_deleted_resource(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, _ = _access(control_session_factory)
    member = await _member(control_session_factory, tenant_id)
    deleted_invoice = await _invoice(control_session_factory, tenant_id, deleted=True)
    with pytest.raises(CrossTenantReferenceError):
        await _grant(
            control, tenant_id, owner, resource_id=deleted_invoice, principal_id=member.user_id
        )


async def test_grant_requires_resource_lookup_configured(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, _ = _access(control_session_factory, resource_lookup=False)
    member = await _member(control_session_factory, tenant_id)
    resource_id = await _invoice(control_session_factory, tenant_id)
    with pytest.raises(AuthorizationError, match="not configured"):
        await _grant(
            control, tenant_id, owner, resource_id=resource_id, principal_id=member.user_id
        )


async def test_grant_is_idempotent_and_revocable(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, audit = _access(control_session_factory)
    resource_id = await _invoice(control_session_factory, tenant_id)
    first = await _grant(
        control, tenant_id, owner, resource_id=resource_id, principal_id=owner.user_id
    )
    assert [entry["action"] for entry in audit.entries] == ["grant.created"]
    second = await _grant(
        control, tenant_id, owner, resource_id=resource_id, principal_id=owner.user_id
    )
    assert first.id == second.id
    assert [entry["action"] for entry in audit.entries] == ["grant.created"]
    await control.revoke_grant(
        tenant_id, first.id, actor_id=owner.user_id, actor_principal=owner
    )
    assert audit.entries[-1]["action"] == "grant.revoked"
    async with control_session_factory() as session:
        remaining = (
            await session.execute(sa.select(ResourceGrant).where(ResourceGrant.id == first.id))
        ).scalar_one_or_none()
    assert remaining is None


async def test_grant_creation_is_race_safe(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, audit = _access(control_session_factory)
    member = await _member(control_session_factory, tenant_id)
    resource_id = await _invoice(control_session_factory, tenant_id)

    winner = control_session_factory()
    try:
        winner.add(
            ResourceGrant(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                resource_type="invoice",
                resource_id=resource_id,
                principal_type="user",
                principal_id=member.user_id,
                permission_code="invoice:approve",
                created_by=owner.user_id,
            )
        )
        await winner.flush()
        loser = asyncio.create_task(
            _grant(
                control,
                tenant_id,
                owner,
                resource_id=resource_id,
                principal_id=member.user_id,
            )
        )
        blocked = await _wait_for_lock_wait(control_session_factory)
        await winner.commit()
        grant = await loser
    finally:
        await winner.close()

    assert blocked, "concurrent grant insert did not wait on the unique index"
    assert grant.permission_code == "invoice:approve"
    assert audit.entries == []
    assert await _grant_exists(control_session_factory, tenant_id, resource_id)


async def test_revoke_requires_resource_share(control_session_factory):
    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, _ = _access(control_session_factory)
    member = await _member(control_session_factory, tenant_id)
    resource_id = await _invoice(control_session_factory, tenant_id)
    grant = await _grant(
        control, tenant_id, owner, resource_id=resource_id, principal_id=member.user_id
    )
    auditor = await _owner_with_grant_permissions(
        control_session_factory, tenant_id, frozenset({"resource:read"})
    )
    with pytest.raises(AuthorizationError, match="resource:share"):
        await control.revoke_grant(
            tenant_id, grant.id, actor_id=auditor.user_id, actor_principal=auditor
        )
    assert await _grant_exists(control_session_factory, tenant_id, resource_id)


async def test_transfer_resource_updates_ownership_and_audits(
    control_session_factory, async_engine
):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from tests.integration.test_session_isolation import _session

    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, audit = _access(control_session_factory)
    async with await _session(
        async_sessionmaker(async_engine, expire_on_commit=False), tenant_id
    ) as session:
        org_a, org_b, team = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        await session.add(Organization(id=org_a, name="A", slug=f"a-{org_a.hex[:6]}"))
        await session.add(Organization(id=org_b, name="B", slug=f"b-{org_b.hex[:6]}"))
        await session.add(Team(id=team, organization_id=org_a, name="T", slug=f"t-{team.hex[:6]}"))
        invoice_id = uuid.uuid4()
        await session.add(
            Invoice(
                id=invoice_id,
                number=f"INV-{invoice_id.hex[:6]}",
                organization_id=org_a,
                team_id=team,
            )
        )
        await session.flush()
        await control.transfer_resource(
            session,
            resource_type="invoice",
            resource_id=invoice_id,
            to_organization_id=org_b,
            to_team_id=None,
            actor_id=owner.user_id,
            actor_principal=owner,
        )
        row = (
            await session.execute(
                sa.select(Invoice.organization_id, Invoice.team_id).where(Invoice.id == invoice_id)
            )
        ).one()
    assert row == (org_b, None)
    entry = audit.entries[-1]
    assert entry["action"] == "resource.owner_changed"
    metadata = entry["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["from"] == f"{org_a}:{team}"
    assert metadata["to"] == f"{org_b}:None"


async def test_transfer_preserves_and_revokes_grants(control_session_factory, async_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from tests.integration.test_session_isolation import _session

    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, _ = _access(control_session_factory)
    member = await _member(control_session_factory, tenant_id)
    resource_id = await _invoice(control_session_factory, tenant_id)
    await _grant(
        control, tenant_id, owner, resource_id=resource_id, principal_id=member.user_id
    )
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
    org_a, org_b, team = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    async with await _session(session_factory, tenant_id) as session:
        await session.add(Organization(id=org_a, name="A", slug=f"a-{org_a.hex[:6]}"))
        await session.add(Organization(id=org_b, name="B", slug=f"b-{org_b.hex[:6]}"))
        await session.add(Team(id=team, organization_id=org_a, name="T", slug=f"t-{team.hex[:6]}"))
        await session.flush()
        await control.transfer_resource(
            session,
            resource_type="invoice",
            resource_id=resource_id,
            to_organization_id=org_b,
            to_team_id=None,
            actor_id=owner.user_id,
            actor_principal=owner,
        )
        await session.commit()
    assert await _grant_exists(control_session_factory, tenant_id, resource_id)
    async with await _session(session_factory, tenant_id) as session:
        await control.transfer_resource(
            session,
            resource_type="invoice",
            resource_id=resource_id,
            to_organization_id=org_a,
            to_team_id=team,
            actor_id=owner.user_id,
            actor_principal=owner,
            revoke_grants=True,
        )
        await session.commit()
    assert not await _grant_exists(control_session_factory, tenant_id, resource_id)


async def test_transfer_requires_resource_share(control_session_factory, async_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from tests.integration.test_session_isolation import _session

    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(
        control_session_factory, tenant_id, frozenset({"invoice:approve"})
    )
    control, _ = _access(control_session_factory)
    resource_id = await _invoice(control_session_factory, tenant_id)
    async with await _session(
        async_sessionmaker(async_engine, expire_on_commit=False), tenant_id
    ) as session:
        with pytest.raises(AuthorizationError, match="resource:share"):
            await control.transfer_resource(
                session,
                resource_type="invoice",
                resource_id=resource_id,
                to_organization_id=None,
                to_team_id=None,
                actor_id=owner.user_id,
                actor_principal=owner,
            )


async def test_move_team_updates_organization_and_audits(control_session_factory, async_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from tests.integration.test_session_isolation import _session

    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, audit = _access(control_session_factory)
    async with await _session(
        async_sessionmaker(async_engine, expire_on_commit=False), tenant_id
    ) as session:
        org_a, org_b, team = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        await session.add(Organization(id=org_a, name="A", slug=f"a-{org_a.hex[:6]}"))
        await session.add(Organization(id=org_b, name="B", slug=f"b-{org_b.hex[:6]}"))
        await session.add(Team(id=team, organization_id=org_a, name="T", slug=f"t-{team.hex[:6]}"))
        await session.flush()
        await control.move_team(
            session,
            team_id=team,
            to_organization_id=org_b,
            actor_id=owner.user_id,
            actor_principal=owner,
            revoke_grants=True,
        )
        moved = (
            await session.execute(sa.select(Team.organization_id).where(Team.id == team))
        ).scalar_one()
    assert moved == org_b
    entry = audit.entries[-1]
    assert entry["action"] == "team.moved"
    metadata = entry["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["team"] == str(team)
    assert metadata["from"] == str(org_a)
    assert metadata["to"] == str(org_b)


async def test_move_team_cascades_owned_resources(control_session_factory, async_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from tests.integration.test_session_isolation import _session

    tenant_id = await _tenant(control_session_factory)
    owner = await _owner_with_grant_permissions(control_session_factory, tenant_id)
    control, audit = _access(control_session_factory)
    member = await _member(control_session_factory, tenant_id)
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
    org_a, org_b, team = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    async with await _session(session_factory, tenant_id) as session:
        await session.add(Organization(id=org_a, name="A", slug=f"a-{org_a.hex[:6]}"))
        await session.add(Organization(id=org_b, name="B", slug=f"b-{org_b.hex[:6]}"))
        await session.add(Team(id=team, organization_id=org_a, name="T", slug=f"t-{team.hex[:6]}"))
        await session.commit()
    resource_id = await _invoice(
        control_session_factory, tenant_id, organization_id=org_a, team_id=team
    )
    await _grant(
        control, tenant_id, owner, resource_id=resource_id, principal_id=member.user_id
    )
    async with await _session(session_factory, tenant_id) as session:
        await control.move_team(
            session,
            team_id=team,
            to_organization_id=org_b,
            actor_id=owner.user_id,
            actor_principal=owner,
            revoke_grants=True,
        )
        row = (
            await session.execute(
                sa.select(Team.organization_id, Invoice.organization_id)
                .select_from(Team)
                .join(Invoice, Invoice.team_id == Team.id)
                .where(Team.id == team)
            )
        ).one()
        await session.commit()
    assert row == (org_b, org_b)
    assert [entry["action"] for entry in audit.entries] == ["grant.created", "team.moved"]
    assert not await _grant_exists(control_session_factory, tenant_id, resource_id)


async def test_transfer_and_move_team_require_tenant_session(control_session_factory):
    control, _ = _access(control_session_factory)
    owner = Principal(kind=PrincipalKind.USER, id=uuid.uuid4(), user_id=uuid.uuid4())
    with pytest.raises(InvalidReference, match="tenant session"):
        await control.transfer_resource(
            object(),
            resource_type="invoice",
            resource_id=uuid.uuid4(),
            to_organization_id=None,
            to_team_id=None,
            actor_id=None,
            actor_principal=owner,
        )
    with pytest.raises(InvalidReference, match="tenant session"):
        await control.move_team(
            object(),
            team_id=uuid.uuid4(),
            to_organization_id=uuid.uuid4(),
            actor_id=None,
            actor_principal=owner,
        )
