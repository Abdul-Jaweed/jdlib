from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from jdlib._uuid import uuid7
from jdlib.models.base import (
    OwnableByOrg,
    OwnableByTeam,
    SoftDelete,
    TenantBase,
    TenantRouted,
    Timestamped,
    ownership_constraints,
)


class Invoice(TenantBase, TenantRouted, Timestamped, SoftDelete, OwnableByOrg, OwnableByTeam):
    __tablename__ = "invoices"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    number: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="draft")

    __table_args__ = (
        *ownership_constraints(),
        sa.Index(
            "uq_invoices_tenant_id_number",
            "tenant_id",
            "number",
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
        ),
    )


class LineItem(TenantBase, TenantRouted, Timestamped):
    __tablename__ = "line_items"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    invoice_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    amount_cents: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["tenant_id", "invoice_id"],
            ["invoices.tenant_id", "invoices.id"],
            ondelete="CASCADE",
        ),
    )
