from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from jdlib._uuid import uuid7
from jdlib.control.base import ControlBase
from jdlib.control.enums import (
    MigrationStatus,
    PlacementStrategy,
    RelocationPhase,
    TenantStatus,
    sql_in,
)


class Tenant(ControlBase):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    slug: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default=TenantStatus.PROVISIONING.value
    )
    suspended_reason: Mapped[str | None] = mapped_column(sa.Text)
    parent_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )
    suspended_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    archived_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    __table_args__ = (
        sa.CheckConstraint(sql_in("status", TenantStatus), name="status"),
        sa.CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'", name="slug_format"),
    )


class TenantPlacement(ControlBase):
    __tablename__ = "tenant_placements"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    strategy: Mapped[str] = mapped_column(sa.Text, nullable=False)
    target_handle: Mapped[str] = mapped_column(sa.Text, nullable=False)
    region: Mapped[str | None] = mapped_column(sa.Text)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(sql_in("strategy", PlacementStrategy), name="strategy"),
    )


class TenantMigrationState(ControlBase):
    __tablename__ = "tenant_migration_states"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    current_version: Mapped[str | None] = mapped_column(sa.Text)
    desired_version: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default=MigrationStatus.PENDING.value
    )
    last_error: Mapped[str | None] = mapped_column(sa.Text)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(sql_in("status", MigrationStatus), name="status"),
    )


class TenantRelocation(ControlBase):
    __tablename__ = "tenant_relocations"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid, sa.ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True
    )
    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    from_strategy: Mapped[str] = mapped_column(sa.Text, nullable=False)
    from_target_handle: Mapped[str] = mapped_column(sa.Text, nullable=False)
    from_region: Mapped[str | None] = mapped_column(sa.Text)
    to_strategy: Mapped[str] = mapped_column(sa.Text, nullable=False)
    to_target_handle: Mapped[str] = mapped_column(sa.Text, nullable=False)
    to_region: Mapped[str | None] = mapped_column(sa.Text)
    status: Mapped[str] = mapped_column(
        sa.Text, nullable=False, default=RelocationPhase.PENDING.value
    )
    started_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    verified_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    flipped_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(sa.Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)

    __table_args__ = (
        sa.CheckConstraint(sql_in("from_strategy", PlacementStrategy), name="from_strategy"),
        sa.CheckConstraint(sql_in("to_strategy", PlacementStrategy), name="to_strategy"),
        sa.CheckConstraint(sql_in("status", RelocationPhase), name="status"),
        sa.Index(
            "uq_tenant_relocations_active",
            "tenant_id",
            unique=True,
            postgresql_where=sa.text(
                "status NOT IN ('completed', 'failed', 'rolled_back')"
            ),
        ),
    )
