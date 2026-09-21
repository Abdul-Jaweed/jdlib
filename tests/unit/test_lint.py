from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from jdlib.control.base import ControlBase
from jdlib.lint import assert_clean, lint_metadata
from jdlib.models.base import TenantBase, TenantOwned


def test_framework_metadata_is_clean():
    import jdlib.control.models  # noqa: F401
    import jdlib.models.audit  # noqa: F401
    import jdlib.models.org  # noqa: F401
    import jdlib.models.settings  # noqa: F401

    issues = lint_metadata([ControlBase.metadata, TenantBase.metadata], rls_enabled=True)
    assert issues == []


def test_tenant_owned_without_routed_is_l17_violation():
    class BadBase(DeclarativeBase):
        metadata = MetaData()

    class Bad(TenantOwned, BadBase):  # type: ignore[misc]
        __tablename__ = "bad"
        id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)

    issues = lint_metadata([BadBase.metadata])
    assert any(issue.rule == "L17" for issue in issues)


def test_control_model_marked_routed_is_l19_violation():
    class BadControlBase(DeclarativeBase):
        metadata = MetaData(schema="jd_control")

    from jdlib.models.base import TenantRouted

    class BadControl(TenantRouted, BadControlBase):  # type: ignore[misc]
        __tablename__ = "bad_control"
        id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)

    issues = lint_metadata([BadControlBase.metadata])
    assert any(issue.rule == "L19" for issue in issues)


def test_single_column_fk_between_tenant_tables_is_l2_violation():
    class BadBase(DeclarativeBase):
        metadata = MetaData()

    class Parent(BadBase, TenantOwned):
        __tablename__ = "parents"
        id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)

    class Child(BadBase, TenantOwned):
        __tablename__ = "children"
        id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)
        parent_id: Mapped[uuid.UUID] = mapped_column(
            sa.Uuid, sa.ForeignKey("parents.id"), nullable=False
        )

    issues = lint_metadata([BadBase.metadata])
    assert any(issue.rule in {"L2", "L10"} and issue.table == "children" for issue in issues)


def test_assert_clean_raises_schema_lint_error():
    from jdlib.errors import SchemaLintError

    class BadBase(DeclarativeBase):
        metadata = MetaData()

    class Orphan(BadBase, TenantOwned):
        __tablename__ = "orphans"
        id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True)

    with pytest.raises(SchemaLintError) as caught:
        assert_clean([BadBase.metadata])
    assert "orphans" in str(caught.value)


class _Marker:
    pass


def test_tenant_scoped_pk_missing_tenant_id_is_l1_violation():
    metadata = MetaData()
    sa.Table(
        "l1_violation",
        metadata,
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("tenant_id", sa.Uuid, nullable=False),
    )
    issues = lint_metadata([metadata])
    assert any(issue.rule == "L1" for issue in issues)


def test_fk_across_planes_is_l3_violation():
    metadata = MetaData()
    sa.Table(
        "parents",
        metadata,
        sa.Column("id", sa.Uuid, primary_key=True),
        schema="plane_a",
    )
    sa.Table(
        "children",
        metadata,
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("parent_id", sa.Uuid, sa.ForeignKey("plane_a.parents.id")),
        schema="plane_b",
    )
    issues = lint_metadata([metadata])
    assert any(issue.rule == "L3" and issue.table == "children" for issue in issues)


def test_tenant_id_not_leading_pk_is_l4_violation():
    metadata = MetaData()
    sa.Table(
        "l4_violation",
        metadata,
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("tenant_id", sa.Uuid, primary_key=True, nullable=False),
    )
    issues = lint_metadata([metadata])
    assert any(issue.rule == "L4" for issue in issues)


def test_cascade_from_tenants_is_l6_violation():
    metadata = MetaData()
    sa.Table("parents", metadata, sa.Column("id", sa.Uuid, primary_key=True))
    sa.Table(
        "tenants",
        metadata,
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("parent_id", sa.Uuid, sa.ForeignKey("parents.id", ondelete="CASCADE")),
    )
    issues = lint_metadata([metadata])
    assert any(issue.rule == "L6" for issue in issues)


def test_nullable_tenant_id_is_l9_violation():
    metadata = MetaData()
    sa.Table(
        "l9_violation",
        metadata,
        sa.Column("tenant_id", sa.Uuid, primary_key=True, nullable=True),
        sa.Column("id", sa.Uuid, primary_key=True),
    )
    issues = lint_metadata([metadata])
    assert any(issue.rule == "L9" for issue in issues)


def test_tenant_scoped_model_not_tenant_owned_is_l11_violation():
    metadata = MetaData()
    table = sa.Table(
        "l11_violation",
        metadata,
        sa.Column("tenant_id", sa.Uuid, primary_key=True, nullable=False),
        sa.Column("id", sa.Uuid, primary_key=True),
    )
    table.info["jdlib_model"] = _Marker
    issues = lint_metadata([metadata])
    assert any(issue.rule == "L11" for issue in issues)


def test_global_unique_on_tenant_scoped_table_is_l12_violation():
    metadata = MetaData()
    table = sa.Table(
        "l12_violation",
        metadata,
        sa.Column("tenant_id", sa.Uuid, primary_key=True, nullable=False),
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("code", sa.Text, nullable=False),
        sa.UniqueConstraint("code", name="uq_l12_violation_code"),
    )
    table.info["jdlib_model"] = _Marker
    issues = lint_metadata([metadata])
    assert any(issue.rule == "L12" for issue in issues)


def test_rls_enabled_unrouted_table_is_l13_violation():
    metadata = MetaData()
    table = sa.Table(
        "l13_violation",
        metadata,
        sa.Column("tenant_id", sa.Uuid, primary_key=True, nullable=False),
        sa.Column("id", sa.Uuid, primary_key=True),
    )
    table.info["jdlib_model"] = _Marker
    issues = lint_metadata([metadata], rls_enabled=True)
    assert any(issue.rule == "L13" for issue in issues)


def test_team_id_without_ownership_constraints_is_l15_violation():
    metadata = MetaData()
    table = sa.Table(
        "l15_violation",
        metadata,
        sa.Column("tenant_id", sa.Uuid, primary_key=True, nullable=False),
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("team_id", sa.Uuid),
    )
    table.info["jdlib_model"] = _Marker
    issues = lint_metadata([metadata])
    assert any(issue.rule == "L15" for issue in issues)
