from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from jdlib._uuid import uuid7
from jdlib.control.enums import ActorType, sql_in
from jdlib.models.base import TenantBase, TenantRouted


class AuditEvent(TenantBase, TenantRouted):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid7)
    actor_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    action: Mapped[str] = mapped_column(sa.Text, nullable=False)
    # Security audit vocabulary (directive §4): a stable event name, the outcome
    # and the component the event came from. Nullable/defaulted so rows written
    # before the vocabulary existed remain readable.
    event_type: Mapped[str | None] = mapped_column(sa.Text)
    outcome: Mapped[str] = mapped_column(
        sa.Text, nullable=False, server_default=sa.text("'SUCCESS'")
    )
    source: Mapped[str | None] = mapped_column(sa.Text)
    target_type: Mapped[str | None] = mapped_column(sa.Text)
    target_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
    metadata_json: Mapped[dict[str, object]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    )
    ip: Mapped[str | None] = mapped_column(INET)
    request_id: Mapped[str | None] = mapped_column(sa.Text)
    correlation_id: Mapped[str | None] = mapped_column(sa.Text)
    trace_id: Mapped[str | None] = mapped_column(sa.Text)
    occurred_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.CheckConstraint(sql_in("actor_type", ActorType), name="actor_type"),
        sa.Index("ix_audit_events_tenant_id_occurred_at", "tenant_id", "occurred_at"),
        sa.Index("ix_audit_events_tenant_id_event_type", "tenant_id", "event_type"),
        sa.Index("ix_audit_events_tenant_id_target_type_target_id",
                 "tenant_id", "target_type", "target_id"),
    )
