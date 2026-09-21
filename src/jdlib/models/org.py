from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from jdlib._uuid import uuid7
from jdlib.models.base import SoftDelete, TenantBase, TenantRouted, Timestamped


class Organization(TenantBase, TenantRouted, Timestamped, SoftDelete):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    parent_organization_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    slug: Mapped[str] = mapped_column(sa.Text, nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "parent_organization_id"],
            ["organizations.tenant_id", "organizations.id"],
            ondelete="RESTRICT",
        ),
        sa.Index(
            "uq_organizations_tenant_id_slug",
            "tenant_id",
            "slug",
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
        ),
        sa.Index("ix_organizations_tenant_id_parent_organization_id",
                 "tenant_id", "parent_organization_id"),
    )


class Team(TenantBase, TenantRouted, Timestamped, SoftDelete):
    __tablename__ = "teams"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    organization_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    slug: Mapped[str] = mapped_column(sa.Text, nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "organization_id"],
            ["organizations.tenant_id", "organizations.id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("tenant_id", "id", "organization_id"),
        sa.Index(
            "uq_teams_tenant_id_organization_id_slug",
            "tenant_id",
            "organization_id",
            "slug",
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
        ),
        sa.Index("ix_teams_tenant_id_organization_id", "tenant_id", "organization_id"),
    )
