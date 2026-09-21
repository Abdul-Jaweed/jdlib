from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from jdlib._uuid import uuid7
from jdlib.control.models import (
    ApiKey,
    IdentityLink,
    Invitation,
    Membership,
    ServiceAccount,
    Tenant,
    User,
)


def _new_tenant(connection: sa.Connection, slug: str) -> uuid.UUID:
    tenant_id = uuid7()
    connection.execute(
        sa.insert(Tenant.__table__).values(id=tenant_id, slug=slug, name=slug, status="active")
    )
    return tenant_id


def test_user_email_partial_unique_and_citext(control_engine, control_metadata):
    with control_engine.begin() as connection:
        connection.execute(
            sa.insert(User.__table__).values(
                id=uuid7(), email="Alice@Example.com", display_name="Alice", status="active"
            )
        )
        connection.execute(
            sa.insert(User.__table__).values(
                id=uuid7(), email=None, display_name="NoMail", status="active"
            )
        )
        connection.execute(
            sa.insert(User.__table__).values(
                id=uuid7(), email=None, display_name="NoMail2", status="active"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(User.__table__).values(
                    id=uuid7(), email="alice@example.com", display_name="Dup", status="active"
                )
            )


def test_identity_link_unique_issuer_subject(control_engine, control_metadata):
    with control_engine.begin() as connection:
        user_id = uuid7()
        connection.execute(
            sa.insert(User.__table__).values(id=user_id, status="active")
        )
        connection.execute(
            sa.insert(IdentityLink.__table__).values(
                id=uuid7(), user_id=user_id, issuer="https://idp", subject="abc"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(IdentityLink.__table__).values(
                    id=uuid7(), user_id=user_id, issuer="https://idp", subject="abc"
                )
            )


def test_service_account_name_unique_per_tenant(control_engine, control_metadata):
    with control_engine.begin() as connection:
        tenant_a = _new_tenant(connection, "sa-tenant-a")
        tenant_b = _new_tenant(connection, "sa-tenant-b")
        connection.execute(
            sa.insert(ServiceAccount.__table__).values(
                tenant_id=tenant_a, id=uuid7(), name="worker", status="active"
            )
        )
        connection.execute(
            sa.insert(ServiceAccount.__table__).values(
                tenant_id=tenant_b, id=uuid7(), name="worker", status="active"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(ServiceAccount.__table__).values(
                    tenant_id=tenant_a, id=uuid7(), name="worker", status="active"
                )
            )


def test_api_key_prefix_globally_unique_and_sa_scoped(control_engine, control_metadata):
    with control_engine.begin() as connection:
        tenant_a = _new_tenant(connection, "key-tenant-a")
        tenant_b = _new_tenant(connection, "key-tenant-b")
        sa_id = uuid7()
        sa_b_id = uuid7()
        connection.execute(
            sa.insert(ServiceAccount.__table__).values(
                tenant_id=tenant_a, id=sa_id, name="svc", status="active"
            )
        )
        connection.execute(
            sa.insert(ServiceAccount.__table__).values(
                tenant_id=tenant_b, id=sa_b_id, name="svc", status="active"
            )
        )
        connection.execute(
            sa.insert(ApiKey.__table__).values(
                tenant_id=tenant_a,
                id=uuid7(),
                service_account_id=sa_id,
                key_prefix="jd_abc",
                key_hash="hash",
                status="active",
            )
        )
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(
                sa.insert(ApiKey.__table__).values(
                    tenant_id=tenant_b,
                    id=uuid7(),
                    service_account_id=sa_b_id,
                    key_prefix="jd_abc",
                    key_hash="hash",
                    status="active",
                )
            )
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(
                sa.insert(ApiKey.__table__).values(
                    tenant_id=tenant_a,
                    id=uuid7(),
                    service_account_id=sa_b_id,
                    key_prefix="jd_cross",
                    key_hash="hash",
                    status="active",
                )
            )


def test_membership_unique_per_tenant(control_engine, control_metadata):
    with control_engine.begin() as connection:
        tenant_a = _new_tenant(connection, "mem-tenant-a")
        tenant_b = _new_tenant(connection, "mem-tenant-b")
        user_id = uuid7()
        connection.execute(sa.insert(User.__table__).values(id=user_id, status="active"))
        connection.execute(
            sa.insert(Membership.__table__).values(
                tenant_id=tenant_a, id=uuid7(), user_id=user_id, status="active"
            )
        )
        connection.execute(
            sa.insert(Membership.__table__).values(
                tenant_id=tenant_b, id=uuid7(), user_id=user_id, status="active"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(Membership.__table__).values(
                    tenant_id=tenant_a, id=uuid7(), user_id=user_id, status="active"
                )
            )


def test_invitation_single_pending_per_email_scope(control_engine, control_metadata):
    from jdlib.control.models import Role

    with control_engine.begin() as connection:
        tenant_id = _new_tenant(connection, "inv-tenant")
        role_id = uuid7()
        connection.execute(
            sa.insert(Role.__table__).values(
                tenant_id=tenant_id, id=role_id, name="member", is_system=False
            )
        )
        base = {
            "tenant_id": tenant_id,
            "email": "invitee@example.com",
            "scope_type": "tenant",
            "role_id": role_id,
            "status": "pending",
            "expires_at": sa.func.now(),
        }
        connection.execute(
            sa.insert(Invitation.__table__).values(
                id=uuid7(), token_id="tok-1", token_hash="hash", **base
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(Invitation.__table__).values(
                    id=uuid7(), token_id="tok-2", token_hash="hash", **base
                )
            )
