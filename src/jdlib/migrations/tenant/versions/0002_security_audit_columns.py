"""Security audit columns on ``audit_events`` (directive §4).

Adds the stable event vocabulary columns used by
:class:`jdlib.security.audit.SecurityAuditEvent`:

* ``event_type``  — stable event name (``AUTHZ_DENY``, ``TENANT_PURGED``, …),
* ``outcome``     — ``SUCCESS`` / ``FAILURE`` / ``DENIED`` / ``ERROR``,
* ``source``      — ``API`` / ``GATEWAY`` / ``SERVICE`` / ``SYSTEM`` /
  ``BACKGROUND_JOB`` / ``CLI``,

plus an index the export path filters on.

Every step is guarded by an inspector, because the baseline revision
(``0001_tenant_baseline``) creates its tables from the live metadata: a database
initialised *after* the model gained these columns already has them, and a
database initialised earlier does not. The guard makes ``alembic upgrade head``
correct in both cases instead of failing with ``DuplicateColumn`` — which is
what the integration suite caught the first time this migration was written.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_security_audit_columns"
down_revision = "0001_tenant_baseline"
branch_labels = None
depends_on = None

_INDEX_NAME = "ix_audit_events_tenant_id_event_type"


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("audit_events")}

    if "event_type" not in columns:
        op.add_column("audit_events", sa.Column("event_type", sa.Text(), nullable=True))
    if "outcome" not in columns:
        op.add_column(
            "audit_events",
            sa.Column("outcome", sa.Text(), nullable=False, server_default=sa.text("'SUCCESS'")),
        )
    if "source" not in columns:
        op.add_column("audit_events", sa.Column("source", sa.Text(), nullable=True))

    if _INDEX_NAME not in {index["name"] for index in inspector.get_indexes("audit_events")}:
        op.create_index(_INDEX_NAME, "audit_events", ["tenant_id", "event_type"], unique=False)


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("audit_events")}

    if _INDEX_NAME in {index["name"] for index in inspector.get_indexes("audit_events")}:
        op.drop_index(_INDEX_NAME, table_name="audit_events")
    for name in ("source", "outcome", "event_type"):
        if name in columns:
            op.drop_column("audit_events", name)
