"""The operator step: migrate the control plane, create a tenant, provision it.

Run once before the first request. It is a separate entry point on purpose -- an application that
migrates and provisions while it starts does both on every worker, and a half-applied provisioning
that a restart retries is the failure this split exists to avoid.

    python -m examples.enterprise.app.bootstrap --slug acme --name "Acme Inc"

Two roles, and this is the step that needs both: the **owner** DSN
(`JDLIB_EXAMPLE_MIGRATION_DSN`) migrates, creates the tenant and installs the policies, while the
**runtime** DSN (the library's `JDLIB_CONTROL_DSN`) names the role the policies are installed
*for*.
A serving process needs only the runtime DSN -- which is why that one is required by the settings
and this one is not: the request path must not be able to reach the owner's credentials.
"""

from __future__ import annotations

import argparse
import asyncio

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from examples.enterprise.app.configuration.settings import ExampleSettings
from examples.enterprise.app.dataplane import install_tenant_rls, shared_strategy
from examples.enterprise.app.dsn import async_dsn, control_dsn, sync_dsn
from jdlib import TenancyConfig
from jdlib.control.audit import DatabaseAuditSink
from jdlib.control.enums import PlacementStrategy
from jdlib.control.registry import TenantRegistry
from jdlib.errors import ProvisioningError
from jdlib.migrations.runner import MigrationRunner


def _role_of(database_url: str) -> str:
    """The role the DSN connects as: the role the policies are created for."""
    username = sa.engine.make_url(database_url).username
    if username is None:
        raise ProvisioningError("the DSN names no role, so no policy can be installed for one")
    return username


def _migration_dsn() -> str:
    """The owner's DSN, or a refusal that names the variable rather than a connection error."""
    dsn = ExampleSettings().migration_dsn  # type: ignore[call-arg]  # env-filled
    if not dsn:
        raise ProvisioningError(
            "the operator step needs the owner's DSN: export JDLIB_EXAMPLE_MIGRATION_DSN. "
            "The request path does not need it, and must not hold it."
        )
    return dsn


async def bootstrap(*, slug: str, name: str) -> str:
    """Migrate, create the tenant, provision it, install the policies, and return the tenant id."""
    config = TenancyConfig()  # type: ignore[call-arg]  # pydantic-settings fills `context` from env
    url = _migration_dsn()
    app_role = _role_of(sync_dsn(control_dsn(config)))
    engine = create_async_engine(async_dsn(url))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        runner = MigrationRunner(url)
        runner.upgrade_control()

        # The tenant plane's tables are created by `registry.provision` below: the shared strategy's
        # `migrate` runs the library's tenant migration, which creates every table registered on
        # `TenantBase.metadata` -- the library's and this application's, because `app.models` is
        # imported by `dataplane`. (`provision_tenant_schema` is the *schema-per-tenant* path and
        # refuses a deployment schema like `public`; see `dataplane.provision_tenant_schema`.)
        registry = TenantRegistry(
            session_factory=sessions,
            strategies={PlacementStrategy.SHARED: shared_strategy(engine)},
            runner=runner,
            audit=DatabaseAuditSink(sessions),
        )
        tenant = await registry.create(
            slug=slug, name=name, strategy=PlacementStrategy.SHARED, target_handle="default"
        )
        await registry.provision(tenant.id)

        # Policies last: a policy cannot be installed on a table that does not exist yet, and the
        # privileges are granted here because the library deliberately grants none.
        await install_tenant_rls(url, "public", app_role=app_role)
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
