from __future__ import annotations

from alembic import op
from sqlalchemy import text

from jdlib.control.base import ControlBase

revision = "0001_control_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(text('CREATE SCHEMA IF NOT EXISTS "jd_control"'))
    bind.execute(text("CREATE EXTENSION IF NOT EXISTS citext"))
    ControlBase.metadata.create_all(bind=bind, checkfirst=True)


def downgrade() -> None:
    ControlBase.metadata.drop_all(bind=op.get_bind(), checkfirst=True)
