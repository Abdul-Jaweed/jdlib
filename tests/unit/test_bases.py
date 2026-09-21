import uuid

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from jdlib.control.base import CONTROL_SCHEMA, ControlBase
from jdlib.models.base import (
    SoftDelete,
    TenantBase,
    TenantOwned,
    TenantRouted,
    Timestamped,
    ownership_constraints,
)


class ControlProbe(ControlBase):
    __tablename__ = "control_probe"
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)


class TenantProbe(TenantBase, TenantRouted, Timestamped, SoftDelete):
    __tablename__ = "tenant_probe"
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)


def test_control_metadata_uses_control_schema():
    assert ControlBase.metadata.schema == CONTROL_SCHEMA == "jd_control"
    assert ControlProbe.__table__.schema == "jd_control"


def test_tenant_metadata_is_unqualified():
    assert TenantBase.metadata.schema is None
    assert TenantProbe.__table__.schema is None


def test_tenant_routed_subclasses_tenant_owned():
    assert issubclass(TenantRouted, TenantOwned)


def test_tenant_scoped_pk_leads_with_tenant_id():
    pk = TenantProbe.__table__.primary_key
    assert [column.name for column in pk.columns] == ["tenant_id", "id"]


def test_mixins_contribute_columns():
    names = {column.name for column in TenantProbe.__table__.columns}
    assert {"tenant_id", "created_at", "updated_at", "deleted_at"} <= names
    assert all(
        column.type.timezone for column in TenantProbe.__table__.columns
        if column.name in {"created_at", "updated_at", "deleted_at"}
    )


def test_ownership_constraints_shape():
    constraints = ownership_constraints()
    kinds = [type(constraint).__name__ for constraint in constraints]
    assert kinds == ["CheckConstraint", "ForeignKeyConstraint", "ForeignKeyConstraint"]
    assert {constraint.name for constraint in constraints} == {
        "team_requires_org",
        "organization",
        "team",
    }
