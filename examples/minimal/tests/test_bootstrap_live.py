"""The operator step against a real PostgreSQL (directive §27: installation and startup).

The example's claim is that it *runs*, so this test runs it: migrate the control plane, create a
tenant, provision it, and read the result back from the database rather than from the object the
call returned. A provisioning path that answers success and stores nothing is exactly the defect a
read-back catches and a return-value assertion does not.

The database is the repository's own convention: `JDLIB_EXAMPLE_DATABASE_URL` when a lab provides
one, otherwise a throwaway `postgres:16` container. No Docker and no URL means the test skips with
that reason -- never a silent pass.
"""

from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa

from jdlib.control.base import CONTROL_SCHEMA
from jdlib.control.enums import TenantStatus

pytestmark = pytest.mark.integration


async def test_bootstrap_provisions_a_tenant_and_stores_it(example_database: str) -> None:
    from examples.minimal.app.bootstrap import bootstrap

    tenant_id = await bootstrap(slug="acme", name="Acme Inc")
    assert uuid.UUID(tenant_id)

    engine = sa.create_engine(example_database, future=True)
    try:
        with engine.connect() as connection:
            row = connection.execute(
                sa.text(
                    f'SELECT slug, status FROM "{CONTROL_SCHEMA}".tenants WHERE slug = :slug'
                ),
                {"slug": "acme"},
            ).one()
    finally:
        engine.dispose()
    assert row.slug == "acme"
    assert row.status == TenantStatus.ACTIVE.value
