from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa

testing = pytest.importorskip("typer.testing")

from jdlib.integrations.cli import app  # noqa: E402


def test_tenant_create_records_platform_audit(
    postgres_url, control_engine, control_metadata
):
    slug = f"cli-{uuid.uuid4().hex[:8]}"
    result = testing.CliRunner().invoke(
        app,
        [
            "tenant",
            "create",
            "--slug",
            slug,
            "--name",
            "CLI Tenant",
            "--database-url",
            postgres_url,
        ],
    )
    assert result.exit_code == 0, result.output
    with control_engine.connect() as connection:
        row = connection.execute(
            sa.text(
                "SELECT action, actor_type, metadata AS metadata_json"
                " FROM jd_control.platform_audit_events"
                " WHERE metadata ->> 'slug' = :slug"
            ),
            {"slug": slug},
        ).one()
    assert row.action == "tenant.created"
    assert row.actor_type == "system"
    assert row.metadata_json["slug"] == slug
