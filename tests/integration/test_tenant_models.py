from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from jdlib._uuid import uuid7
from jdlib.models.audit import AuditEvent
from jdlib.models.base import TenantBase
from jdlib.models.org import Organization, Team
from jdlib.models.settings import TenantSetting
from tests.support.invoice import Invoice


@pytest.fixture(scope="session")
def tenant_metadata(postgres_url: str, control_metadata):
    from sqlalchemy import create_engine

    engine = create_engine(postgres_url, future=True)
    with engine.begin() as connection:
        connection.exec_driver_sql('SET search_path TO "jt_test"')
        TenantBase.metadata.create_all(connection)
    yield engine


def _seed_tenant(engine, slug: str):
    from jdlib.control.models import Tenant

    tenant_id = uuid7()
    with engine.begin() as connection:
        connection.execute(
            sa.insert(Tenant.__table__).values(
                id=tenant_id, slug=slug, name=slug, status="active"
            )
        )
    return tenant_id


def test_org_tree_and_unique_slug(tenant_metadata):
    engine = tenant_metadata
    tenant_id = _seed_tenant(engine, "org-tenant")
    root_id, child_id = uuid7(), uuid7()
    with engine.begin() as connection:
        connection.exec_driver_sql('SET search_path TO "jt_test"')
        connection.execute(
            sa.insert(Organization.__table__).values(
                tenant_id=tenant_id, id=root_id, name="Root", slug="root"
            )
        )
        connection.execute(
            sa.insert(Organization.__table__).values(
                tenant_id=tenant_id, id=child_id, name="Child", slug="child",
                parent_organization_id=root_id,
            )
        )
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(
                sa.insert(Organization.__table__).values(
                    tenant_id=tenant_id, id=uuid7(), name="Dup", slug="root"
                )
            )


def test_team_composite_ownership_and_resource_consistency(tenant_metadata):
    engine = tenant_metadata
    tenant_id = _seed_tenant(engine, "team-tenant")
    other_tenant = _seed_tenant(engine, "team-tenant-2")
    org_id, other_org_id, team_id = uuid7(), uuid7(), uuid7()
    with engine.begin() as connection:
        connection.exec_driver_sql('SET search_path TO "jt_test"')
        connection.execute(
            sa.insert(Organization.__table__).values(
                tenant_id=tenant_id, id=org_id, name="Org", slug="org"
            )
        )
        connection.execute(
            sa.insert(Organization.__table__).values(
                tenant_id=tenant_id, id=other_org_id, name="Org2", slug="org2"
            )
        )
        connection.execute(
            sa.insert(Team.__table__).values(
                tenant_id=tenant_id, id=team_id, organization_id=org_id,
                name="Team", slug="team",
            )
        )
        connection.execute(
            sa.insert(Invoice.__table__).values(
                tenant_id=tenant_id, id=uuid7(), number="INV-1",
                organization_id=org_id, team_id=team_id,
            )
        )
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(
                sa.insert(Invoice.__table__).values(
                    tenant_id=tenant_id, id=uuid7(), number="INV-2",
                    organization_id=other_org_id, team_id=team_id,
                )
            )
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(
                sa.insert(Invoice.__table__).values(
                    tenant_id=tenant_id, id=uuid7(), number="INV-3", team_id=team_id
                )
            )
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(
                sa.insert(Invoice.__table__).values(
                    tenant_id=other_tenant, id=uuid7(), number="INV-4",
                    organization_id=org_id, team_id=team_id,
                )
            )


def test_soft_delete_partial_unique(tenant_metadata):
    engine = tenant_metadata
    tenant_id = _seed_tenant(engine, "soft-tenant")
    with engine.begin() as connection:
        connection.exec_driver_sql('SET search_path TO "jt_test"')
        connection.execute(
            sa.insert(Invoice.__table__).values(
                tenant_id=tenant_id, id=uuid7(), number="INV-9"
            )
        )
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(
                sa.insert(Invoice.__table__).values(
                    tenant_id=tenant_id, id=uuid7(), number="INV-9"
                )
            )
        connection.exec_driver_sql(
            "DELETE FROM invoices WHERE number = 'INV-9'"
        )
        connection.execute(
            sa.insert(Invoice.__table__).values(
                tenant_id=tenant_id, id=uuid7(), number="INV-9"
            )
        )


def test_tenant_setting_pk_and_upsert_shape(tenant_metadata):
    engine = tenant_metadata
    tenant_id = _seed_tenant(engine, "settings-tenant")
    with engine.begin() as connection:
        connection.exec_driver_sql('SET search_path TO "jt_test"')
        connection.execute(
            sa.insert(TenantSetting.__table__).values(
                tenant_id=tenant_id, key="billing.currency", value={"code": "EUR"}
            )
        )
        assert [c.name for c in TenantSetting.__table__.primary_key.columns] == [
            "tenant_id", "key",
        ]


def test_tenant_audit_event_shape(tenant_metadata):
    assert [c.name for c in AuditEvent.__table__.primary_key.columns] == ["tenant_id", "id"]
