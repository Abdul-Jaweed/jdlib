from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from jdlib.control.base import NAMING_CONVENTION


class TenantBase(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class TenantOwned:
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid,
        primary_key=True,
        nullable=False,
        sort_order=-1,
    )


class TenantRouted(TenantOwned):
    pass


class Timestamped:
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )


class SoftDelete:
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))


class OwnableByOrg:
    organization_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)


class OwnableByTeam:
    team_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)


def ownership_constraints() -> tuple[sa.schema.Constraint, ...]:
    return (
        sa.CheckConstraint(
            "team_id IS NULL OR organization_id IS NOT NULL",
            name="team_requires_org",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "organization_id"],
            ["organizations.tenant_id", "organizations.id"],
            name="organization",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "team_id", "organization_id"],
            ["teams.tenant_id", "teams.id", "teams.organization_id"],
            name="team",
            ondelete="RESTRICT",
        ),
    )
