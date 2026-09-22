import uuid

from jdlib.authz.reader import ControlAccessReader
from jdlib.context import Principal, PrincipalKind
from jdlib.control.enums import ScopeType
from jdlib.control.models import (
    Membership,
    ResourceGrant,
    Role,
    RoleBinding,
    RolePermission,
    ServiceAccount,
    Tenant,
    User,
)


async def test_control_reader_reads_status_bindings_and_permissions(
    control_session_factory,
):
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    role_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"authz-{tenant_id.hex[:8]}", name="A", status="active")
        )
        await session.commit()

    async with control_session_factory() as session:
        session.add(User(id=user_id, status="active"))
        session.add(Role(tenant_id=tenant_id, id=role_id, name="member"))
        await session.flush()
        session.add(
            Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=user_id, status="active")
        )
        session.add(
            RolePermission(tenant_id=tenant_id, role_id=role_id, permission_code="resource:read")
        )
        session.add(
            RoleBinding(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                role_id=role_id,
                principal_type="user",
                principal_id=user_id,
                scope_type="tenant",
            )
        )
        await session.commit()

    reader = ControlAccessReader(control_session_factory)
    principal = Principal(kind=PrincipalKind.USER, id=user_id, user_id=user_id)
    assert await reader.tenant_status_of(tenant_id) == "active"
    assert await reader.principal_active(principal) is True
    assert await reader.membership_active(principal, tenant_id) is True
    bindings = await reader.bindings_for(principal, tenant_id, {(ScopeType.TENANT, None)})
    assert [binding.role_id for binding in bindings] == [role_id]
    assert await reader.permissions_by_role(tenant_id, [role_id]) == {
        role_id: frozenset({"resource:read"})
    }
    assert await reader.grants_for(principal, tenant_id, "invoice", uuid.uuid4()) == frozenset()


async def test_control_reader_handles_service_accounts_and_grants(control_session_factory):
    tenant_id = uuid.uuid4()
    account_id = uuid.uuid4()
    resource_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(id=tenant_id, slug=f"authz-{tenant_id.hex[:8]}", name="B", status="active")
        )
        await session.commit()

    async with control_session_factory() as session:
        session.add(
            ServiceAccount(tenant_id=tenant_id, id=account_id, name="bot", status="active")
        )
        session.add(
            ResourceGrant(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                resource_type="invoice",
                resource_id=resource_id,
                principal_type="service_account",
                principal_id=account_id,
                permission_code="resource:read",
            )
        )
        await session.commit()

    reader = ControlAccessReader(control_session_factory)
    principal = Principal(kind=PrincipalKind.SERVICE_ACCOUNT, id=account_id, tenant_id=tenant_id)
    assert await reader.principal_active(principal) is True
    assert await reader.membership_active(principal, tenant_id) is True
    assert await reader.grants_for(principal, tenant_id, "invoice", resource_id) == frozenset(
        {"resource:read"}
    )

    other_tenant_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(
            Tenant(
                id=other_tenant_id,
                slug=f"authz-{other_tenant_id.hex[:8]}",
                name="C",
                status="active",
            )
        )
        await session.commit()
    foreign = Principal(
        kind=PrincipalKind.SERVICE_ACCOUNT, id=account_id, tenant_id=other_tenant_id
    )
    assert await reader.principal_active(foreign) is False


async def test_control_reader_denies_platform_operators(control_session_factory):
    reader = ControlAccessReader(control_session_factory)
    operator = Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4())
    assert await reader.principal_active(operator) is False
    assert await reader.membership_active(operator, uuid.uuid4()) is False
