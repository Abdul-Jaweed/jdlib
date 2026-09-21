from __future__ import annotations

import sqlalchemy as sa

from jdlib.migrations.runner import MigrationRunner


def test_control_baseline_migrates_all_tables(postgres_url: str):
    runner = MigrationRunner(postgres_url)
    runner.upgrade_control()
    engine = sa.create_engine(postgres_url, future=True)
    with engine.connect() as connection:
        tables = set(
            sa.inspect(connection).get_table_names(schema="jd_control")
        )
    expected = {
        "tenants",
        "tenant_placements",
        "tenant_migration_states",
        "tenant_relocations",
        "users",
        "identity_links",
        "platform_operators",
        "service_accounts",
        "api_keys",
        "memberships",
        "roles",
        "role_permissions",
        "role_bindings",
        "resource_grants",
        "invitations",
        "platform_audit_events",
    }
    assert expected <= tables
    assert "alembic_version" in tables


def test_tenant_baseline_creates_schema_tables(postgres_url: str):
    runner = MigrationRunner(postgres_url)
    runner.provision_tenant_schema("jt_migrated")
    engine = sa.create_engine(postgres_url, future=True)
    with engine.connect() as connection:
        tables = set(sa.inspect(connection).get_table_names(schema="jt_migrated"))
    assert {"organizations", "teams", "tenant_settings", "audit_events"} <= tables
    assert "alembic_version" in tables


def test_upgrade_is_idempotent(postgres_url: str):
    runner = MigrationRunner(postgres_url)
    runner.upgrade_control()
    runner.upgrade_control()
    runner.provision_tenant_schema("jt_migrated")
    runner.provision_tenant_schema("jt_migrated")
