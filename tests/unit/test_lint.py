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
