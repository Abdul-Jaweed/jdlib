"""The operator step: migrate the control plane, create a tenant, provision it.

Run once before the first request. It is a separate entry point on purpose -- an application that
migrates and provisions while it starts does both on every worker, and a half-applied provisioning
that a restart retries is the failure this split exists to avoid.

    python -m examples.enterprise.app.bootstrap --slug acme --name "Acme Inc"
"""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from examples.enterprise.app.dsn import async_dsn, control_dsn
from jdlib import TenancyConfig
from jdlib.control.audit import DatabaseAuditSink
from jdlib.control.enums import PlacementStrategy
from jdlib.control.registry import TenantRegistry
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.strategies.shared import SharedSchemaStrategy


async def bootstrap(*, slug: str, name: str) -> str:
    """Migrate, create the tenant, provision it, and return the new tenant id."""
    config = TenancyConfig()  # type: ignore[call-arg]  # pydantic-settings fills `context` from env
    url = control_dsn(config)
    engine = create_async_engine(async_dsn(url))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        runner = MigrationRunner(url)
        runner.upgrade_control()
        registry = TenantRegistry(
            session_factory=sessions,
            strategies={PlacementStrategy.SHARED: SharedSchemaStrategy(engine, "public")},
            runner=runner,
            audit=DatabaseAuditSink(sessions),
        )
        tenant = await registry.create(
            slug=slug, name=name, strategy=PlacementStrategy.SHARED, target_handle="default"
        )
        await registry.provision(tenant.id)
        return str(tenant.id)
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision the enterprise example's first tenant.")
    parser.add_argument("--slug", default="acme")
    parser.add_argument("--name", default="Acme Inc")
    args = parser.parse_args()
    tenant_id = asyncio.run(bootstrap(slug=args.slug, name=args.name))
    print(f"provisioned tenant {args.slug} ({tenant_id})")


if __name__ == "__main__":
    main()
