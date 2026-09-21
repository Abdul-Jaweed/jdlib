from __future__ import annotations

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from jdlib._uuid import uuid7
from jdlib.control.base import CONTROL_SCHEMA
from jdlib.control.models import (
    Tenant,
    TenantMigrationState,
    TenantPlacement,
    TenantRelocation,
)


def _table(model: type) -> sa.Table:
    return model.__table__  # type: ignore[attr-defined]


def test_registry_tables_live_in_control_schema():
    for model in (Tenant, TenantPlacement, TenantMigrationState, TenantRelocation):
        assert _table(model).schema == CONTROL_SCHEMA


def test_placement_pk_is_tenant_id():
    assert [c.name for c in _table(TenantPlacement).primary_key.columns] == ["tenant_id"]


def test_relocation_pk_and_active_unique_index():
    table = _table(TenantRelocation)
    assert [c.name for c in table.primary_key.columns] == ["tenant_id", "id"]
    indexes = {index.name: index for index in table.indexes}
    active = next(
        index for index in indexes.values()
        if index.unique and index.dialect_options["postgresql"].get("where") is not None
    )
    assert "status NOT IN" in str(active.dialect_options["postgresql"]["where"])


def test_tenant_check_constraints_exist():
    table = _table(Tenant)
    names = {constraint.name for constraint in table.constraints
             if isinstance(constraint, sa.CheckConstraint)}
    assert names == {"ck_tenants_status", "ck_tenants_slug_format"}


def test_slug_format_rejected(control_engine, control_metadata):
    with control_engine.begin() as connection, pytest.raises(IntegrityError):
        connection.execute(
            sa.insert(_table(Tenant)).values(
                id=uuid7(), slug="BAD SLUG", name="Bad", status="provisioning"
            )
        )


def test_duplicate_placement_rejected(control_engine, control_metadata):
    tenant_id = uuid7()
    with control_engine.begin() as connection:
        connection.execute(
            sa.insert(_table(Tenant)).values(
                id=tenant_id, slug=f"acme-{tenant_id.hex[:8]}", name="Acme", status="active"
            )
        )
        connection.execute(
            sa.insert(_table(TenantPlacement)).values(
                tenant_id=tenant_id, strategy="shared", target_handle="default"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(_table(TenantPlacement)).values(
                    tenant_id=tenant_id, strategy="schema", target_handle="t_other"
                )
            )


def test_invalid_strategy_rejected(control_engine, control_metadata):
    tenant_id = uuid7()
    with control_engine.begin() as connection:
        connection.execute(
            sa.insert(_table(Tenant)).values(
                id=tenant_id, slug=f"beta-{tenant_id.hex[:8]}", name="Beta", status="active"
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                sa.insert(_table(TenantPlacement)).values(
                    tenant_id=tenant_id, strategy="sharded", target_handle="x"
                )
            )


def test_duplicate_active_relocation_rejected(control_engine, control_metadata):
    tenant_id = uuid7()
    with control_engine.begin() as connection:
        connection.execute(
            sa.insert(_table(Tenant)).values(
                id=tenant_id, slug=f"gamma-{tenant_id.hex[:8]}", name="Gamma", status="active"
            )
        )
        values = {
            "tenant_id": tenant_id,
            "from_strategy": "shared",
            "from_target_handle": "default",
            "to_strategy": "database",
            "to_target_handle": "db-gamma",
            "status": "copying",
        }
        connection.execute(sa.insert(_table(TenantRelocation)).values(id=uuid7(), **values))
        with pytest.raises(IntegrityError):
            connection.execute(sa.insert(_table(TenantRelocation)).values(id=uuid7(), **values))
