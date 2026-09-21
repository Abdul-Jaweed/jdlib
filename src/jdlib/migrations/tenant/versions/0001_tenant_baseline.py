from __future__ import annotations

from alembic import op

from jdlib.models.base import TenantBase

revision = "0001_tenant_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    TenantBase.metadata.create_all(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    TenantBase.metadata.drop_all(bind=op.get_bind(), checkfirst=True)
