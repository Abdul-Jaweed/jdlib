"""Phase 9: the live collectors observe the catalog, not the code.

The directive is explicit that having a ``TenantSession`` proves nothing about the
database, so these tests attack the observation itself on real PostgreSQL: they
install the policies, then break them one way at a time — a dropped policy, an
unforced table, a schema that was never provisioned — and require the evidence to
report what actually happened. A collector that reported the code's intentions
instead of the catalog's state would pass none of them.

The revision collector is attacked the same way: a schema with no revision table,
a schema behind the checkout's head, and a schema at it.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from jdlib.security.compliance.evidence import collect_migration_evidence
from jdlib.security.compliance.session import (
    collect_isolation_evidence,
    collect_schema_revision_evidence,
)
from tests.integration.conftest import TENANT_SCHEMA
from tests.support.invoice import Invoice  # noqa: F401  (registers the tenant-routed table)

UNPROVISIONED_SCHEMA = "jc_unprovisioned"


def _bound_engine(postgres_url: str, schema: str) -> AsyncEngine:
    return create_async_engine(
        sa.engine.make_url(postgres_url)
        .set(drivername="postgresql+asyncpg")
        .render_as_string(hide_password=False),
        connect_args={"server_settings": {"search_path": schema}},
    )


async def test_isolation_evidence_sees_an_enforced_schema(
    rls_engine: AsyncEngine, postgres_url: str
) -> None:
    engine = _bound_engine(postgres_url, TENANT_SCHEMA)
    try:
        record = await collect_isolation_evidence(engine, environment="test")
    finally:
        await engine.dispose()

    assert record.control_id == "JDL-ISO-01"
    assert record.observations["is_enforced"] is True
    assert record.observations["tables_checked"] >= 1
    assert record.observations["tables_missing_rls"] == []
    assert record.observations["tables_missing_force"] == []
    assert record.observations["tables_missing_policy"] == []
    assert record.observations["tables_unprovisioned"] == []


async def test_a_dropped_policy_is_visible_in_the_evidence(
    rls_engine: AsyncEngine, postgres_url: str
) -> None:
    async with rls_engine.begin() as connection:
        await connection.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
        await connection.execute(sa.text("DROP POLICY tenant_isolation ON invoices"))

    engine = _bound_engine(postgres_url, TENANT_SCHEMA)
    try:
        record = await collect_isolation_evidence(engine)
    finally:
        await engine.dispose()

    assert record.observations["is_enforced"] is False
    assert record.observations["tables_missing_policy"] == ["invoices"]
    assert record.observations["tables_missing_rls"] == []


async def test_an_unforced_table_is_visible_in_the_evidence(
    rls_engine: AsyncEngine, postgres_url: str
) -> None:
    async with rls_engine.begin() as connection:
        await connection.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
        await connection.execute(
            sa.text("ALTER TABLE invoices NO FORCE ROW LEVEL SECURITY")
        )

    engine = _bound_engine(postgres_url, TENANT_SCHEMA)
    try:
        record = await collect_isolation_evidence(engine)
    finally:
        await engine.dispose()

    assert record.observations["is_enforced"] is False
    assert record.observations["tables_missing_force"] == ["invoices"]
    assert record.observations["tables_missing_policy"] == []


async def test_an_unprovisioned_schema_is_reported_rather_than_assumed(
    postgres_url: str,
) -> None:
    # The directive's warning, as a test: a schema without the tenant tables is not
    # "isolated", and evidence must not imply that it is.
    engine = _bound_engine(postgres_url, TENANT_SCHEMA)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                sa.text(f'CREATE SCHEMA IF NOT EXISTS "{UNPROVISIONED_SCHEMA}"')
            )
    finally:
        await engine.dispose()

    empty = _bound_engine(postgres_url, UNPROVISIONED_SCHEMA)
    try:
        record = await collect_isolation_evidence(empty)
    finally:
        await empty.dispose()

    assert record.observations["is_enforced"] is False
    assert "invoices" in record.observations["tables_unprovisioned"]
    assert record.observations["tables_checked"] >= 1


async def test_revision_evidence_reports_absence_drift_and_agreement(
    postgres_url: str,
) -> None:
    heads = collect_migration_evidence().observations
    expected = str(heads["tenant_head"])
    assert expected != "0001_tenant_baseline", "the checkout must have moved past the baseline"

    engine = _bound_engine(postgres_url, TENANT_SCHEMA)
    try:
        async with engine.begin() as connection:
            await connection.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
            await connection.execute(sa.text("DROP TABLE IF EXISTS alembic_version"))
            await connection.execute(
                sa.text("CREATE TABLE alembic_version (version_num VARCHAR(64) PRIMARY KEY)")
            )

        absent = await collect_schema_revision_evidence(
            engine, branch="tenant", expected_head=expected
        )
        assert absent.observations["table_present"] is True
        assert absent.observations["current_revisions"] == []
        assert absent.observations["at_head"] is False

        async with engine.begin() as connection:
            await connection.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
            await connection.execute(
                sa.text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                {"revision": "0001_tenant_baseline"},
            )
        drifted = await collect_schema_revision_evidence(
            engine, branch="tenant", expected_head=expected
        )
        assert drifted.observations["current_revision"] == "0001_tenant_baseline"
        assert drifted.observations["at_head"] is False
        assert drifted.observations["expected_head"] == expected

        async with engine.begin() as connection:
            await connection.execute(sa.text(f'SET search_path TO "{TENANT_SCHEMA}"'))
            await connection.execute(
                sa.text("UPDATE alembic_version SET version_num = :revision"),
                {"revision": expected},
            )
        current = await collect_schema_revision_evidence(
            engine, branch="tenant", expected_head=expected
        )
        assert current.observations["at_head"] is True
        assert current.observations["current_revisions"] == [expected]
    finally:
        await engine.dispose()


async def test_revision_evidence_on_a_schema_without_the_table(postgres_url: str) -> None:
    engine = _bound_engine(postgres_url, UNPROVISIONED_SCHEMA)
    try:
        record = await collect_schema_revision_evidence(
            engine, branch="tenant", expected_head="0002_security_audit_columns"
        )
    finally:
        await engine.dispose()

    assert record.observations["table_present"] is False
    assert record.observations["current_revision"] is None
    assert record.observations["at_head"] is False
