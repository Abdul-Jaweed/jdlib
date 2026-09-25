"""The tenant plane's two tables: a resource, and the entities inside it.

Three library conventions are load-bearing, and each one is a control rather than a style:

* `TenantBase` -- the shared metadata object. The library's tenant migration creates every table
  registered on it (`TenantBase.metadata.create_all`), and `install_rls` walks it for tables that
  need a policy. A table built on any other base is created by nothing and protected by nothing.
* `TenantRouted` -- what makes a table *discoverable* as tenant-scoped: `tenant_id` is part of the
  primary key, and the RLS installer finds the table by this mixin rather than by a listing.
* a **composite foreign key** -- `entities (tenant_id, resource_id)` references
  `resources (tenant_id, id)`, so a cross-tenant reference is refused by the database itself, not
  only by the policy engine and not only by application code. This is the third layer of the same
  protection, and the only one that survives a bug in the other two.
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from jdlib.models.base import SoftDelete, TenantBase, TenantRouted, Timestamped

__all__ = ["Entity", "Resource"]

KINDS = ("document", "dataset", "model")
STATUSES = ("active", "archived")


class Resource(TenantBase, TenantRouted, Timestamped, SoftDelete):
    """A tenant-scoped thing the API and the graph both know about."""

    __tablename__ = "resources"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    kind: Mapped[str] = mapped_column(sa.Text, nullable=False, default="document")
    status: Mapped[str] = mapped_column(sa.Text, nullable=False, default="active")
    created_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)

    __table_args__ = (
        sa.UniqueConstraint("tenant_id", "name", name="resource_name_per_tenant"),
        sa.CheckConstraint(
            "kind IN ('document', 'dataset', 'model')", name="resource_kind_known"
        ),
        sa.CheckConstraint(
            "status IN ('active', 'archived')", name="resource_status_known"
        ),
    )


class Entity(TenantBase, TenantRouted, Timestamped, SoftDelete):
    """A named thing inside a resource — the relational side of the graph's `Entity` node."""

    __tablename__ = "entities"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    resource_id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, nullable=False)
    label: Mapped[str] = mapped_column(sa.Text, nullable=False)
    weight: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)

    __table_args__ = (
        # Tenant-first and composite: an entity can only ever point at a resource of its own tenant.
        sa.ForeignKeyConstraint(
            ["tenant_id", "resource_id"],
            ["resources.tenant_id", "resources.id"],
            name="entity_resource_same_tenant",
        ),
        sa.UniqueConstraint("tenant_id", "resource_id", "label", name="entity_label_per_resource"),
        sa.CheckConstraint("weight >= 0", name="entity_weight_non_negative"),
    )
