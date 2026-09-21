from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from jdlib.models.base import TenantBase, TenantRouted


class TenantSetting(TenantBase, TenantRouted):
    __tablename__ = "tenant_settings"

    key: Mapped[str] = mapped_column(sa.Text, primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid)
