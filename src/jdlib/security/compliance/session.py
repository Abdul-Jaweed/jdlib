"""Session-backed evidence collectors (directive §9.5).

These observe infrastructure rather than the checkout: the PostgreSQL catalog for
row-level security, the revision a live schema has actually applied, and the
policy configuration a deployment declares. They live in their own module so that
importing :mod:`jdlib.security.compliance` stays free of the persistence layer.

Two rules run through all of them. First, they never fabricate: a collector that
cannot reach its subject raises, because "no evidence" is a state a report may
describe (``WARN``) but an assumed state is not. Second, having a
:class:`~jdlib.persistence.session.TenantSession` proves nothing about the
database — the isolation collector asks the catalog, exactly as the CLI's
``rls verify`` does, by sharing :func:`jdlib.persistence.strategies.rls.inspect_rls`
with it.
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

from jdlib.context import Clock, SystemClock
from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.rls import inspect_rls
from jdlib.security.compliance.evidence import SecurityEvidence

__all__ = [
    "collect_isolation_evidence",
    "collect_schema_revision_evidence",
]


async def collect_isolation_evidence(
    engine: AsyncEngine,
    *,
    metadata: sa.MetaData | None = None,
    clock: Clock | None = None,
    environment: str | None = None,
) -> SecurityEvidence:
    """Observe row-level security on the schema this engine is bound to.

    The engine must be bound to the schema under test (``search_path``), exactly as
    the CLI's ``rls verify`` requires; a table that cannot be seen is reported as
    unprovisioned rather than assumed to be fine.
    """
    inspection = await inspect_rls(engine, metadata=metadata or TenantBase.metadata)
    return SecurityEvidence(
        control_id="JDL-ISO-01",
        subject="postgresql:row-level-security",
        collected_by="jdlib.security.compliance.collect_isolation_evidence",
        collected_at=(clock or SystemClock()).now(),
        observations={
            "tables_checked": len(inspection.tables_checked),
            "tables_enforced": len(inspection.tables_enforced),
            "tables_missing_rls": list(inspection.tables_missing_rls),
            "tables_missing_force": list(inspection.tables_missing_force),
            "tables_missing_policy": list(inspection.tables_missing_policy),
            "tables_unprovisioned": list(inspection.tables_unprovisioned),
            "is_enforced": inspection.is_enforced,
        },
        reproducible="jdlib rls verify --schema <schema> --app-role <role>",
        environment=environment,
    )


async def collect_schema_revision_evidence(
    engine: AsyncEngine,
    *,
    branch: str,
    expected_head: str,
    clock: Clock | None = None,
    environment: str | None = None,
) -> SecurityEvidence:
    """Observe the revision a live schema has applied, against the expected head.

    ``expected_head`` comes from :func:`collect_migration_evidence`, which reads
    the checkout: the pair is what makes schema drift visible, and neither half is
    useful alone. A schema with no revision table has applied nothing, which is an
    observation (``table_present`` is false) rather than an error.
    """
    revisions: list[str] = []
    present = True
    async with engine.connect() as connection:
        try:
            # A `sa.text` select is untyped, so the scalar type is `Never` and mypy wants the
            # annotation here rather than on the comprehension variable.
            versions: list[Any] = list(
                (
                    await connection.execute(sa.text("SELECT version_num FROM alembic_version"))
                ).scalars()
            )
            rows = [str(version) for version in versions]
        except ProgrammingError:
            present = False
            rows = []
    revisions.extend(str(row) for row in rows)
    return SecurityEvidence(
        control_id="JDL-CONF-01",
        subject=f"postgresql:alembic_version[{branch}]",
        collected_by="jdlib.security.compliance.collect_schema_revision_evidence",
        collected_at=(clock or SystemClock()).now(),
        observations={
            "branch": branch,
            "table_present": present,
            "current_revisions": sorted(revisions),
            "current_revision": revisions[0] if len(revisions) == 1 else None,
            "expected_head": expected_head,
            "at_head": present and revisions == [expected_head],
        },
        reproducible="SELECT version_num FROM alembic_version (on the schema under test)",
        environment=environment,
    )
