from __future__ import annotations

import asyncio
import importlib
import json
import uuid
from collections.abc import Callable, Coroutine, Mapping
from typing import Annotated, Any

import sqlalchemy as sa
import typer
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)

from jdlib.control.base import ControlBase
from jdlib.control.enums import PlacementStrategy
from jdlib.control.models import Tenant, TenantPlacement
from jdlib.control.registry import TenantRegistry
from jdlib.control.session import ControlPlaneSession
from jdlib.errors import JdlibError
from jdlib.lint import lint_metadata
from jdlib.migrations.runner import MigrationRunner
from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.rls import install_rls, verify_rls
from jdlib.persistence.strategies.schema import SchemaPerTenantStrategy
from jdlib.persistence.strategies.shared import SharedSchemaStrategy

Payload = Mapping[str, object] | list[Mapping[str, object]]

app = typer.Typer(no_args_is_help=True)
tenant_app = typer.Typer(no_args_is_help=True)
db_app = typer.Typer(no_args_is_help=True)
rls_app = typer.Typer(no_args_is_help=True)
schema_app = typer.Typer(no_args_is_help=True)
app.add_typer(tenant_app, name="tenant")
app.add_typer(db_app, name="db")
app.add_typer(rls_app, name="rls")
app.add_typer(schema_app, name="schema")

DatabaseUrl = Annotated[str | None, typer.Option("--database-url", envvar="JDLIB_CONTROL_DSN")]
SharedSchema = Annotated[str, typer.Option("--shared-schema")]
JsonOutput = Annotated[bool, typer.Option("--json")]

_ASYNC_DRIVERS = {"postgresql", "postgresql+psycopg", "postgresql+psycopg2"}


class _NoopAudit:
    async def record(
        self,
        *,
        action: str,
        tenant_id: uuid.UUID | None,
        actor_id: uuid.UUID | None,
        metadata: Mapping[str, object] | None = None,
        session: ControlPlaneSession | None = None,
    ) -> None:
        return None


def _require_url(database_url: str | None) -> str:
    if not database_url:
        raise typer.BadParameter("provide --database-url or set JDLIB_CONTROL_DSN")
    return database_url


def _async_url(database_url: str) -> str:
    url = sa.engine.make_url(database_url)
    if url.drivername in _ASYNC_DRIVERS:
        url = url.set(drivername="postgresql+asyncpg")
    return url.render_as_string(hide_password=False)


def _engine(database_url: str) -> AsyncEngine:
    return create_async_engine(_async_url(database_url))


def _bound_engine(database_url: str, schema: str) -> AsyncEngine:
    return create_async_engine(
        _async_url(database_url),
        connect_args={"server_settings": {"search_path": f"{schema}, public"}},
    )


def _import_framework_models() -> None:
    for module in (
        "jdlib.control.models",
        "jdlib.models.audit",
        "jdlib.models.org",
        "jdlib.models.settings",
    ):
        importlib.import_module(module)


def _registry(engine: AsyncEngine, database_url: str, shared_schema: str) -> TenantRegistry:
    runner = MigrationRunner(database_url)
    return TenantRegistry(
        session_factory=async_sessionmaker(engine, expire_on_commit=False),
        strategies={
            PlacementStrategy.SHARED: SharedSchemaStrategy(engine, shared_schema),
            PlacementStrategy.SCHEMA: SchemaPerTenantStrategy(engine, runner),
        },
        runner=runner,
        audit=_NoopAudit(),
    )


def _emit(payload: Payload, as_json: bool) -> None:
    if as_json:
        typer.echo(json.dumps(payload, default=str))
        return
    if isinstance(payload, list):
        for row in payload:
            typer.echo(" ".join(f"{key}={value}" for key, value in row.items()))
        return
    for key, value in payload.items():
        typer.echo(f"{key}={value}")


def _fail(exc: Exception) -> None:
    typer.echo(f"error: {exc}", err=True)
    raise typer.Exit(1) from exc


def _run_sync(work: Callable[[], Payload], as_json: bool) -> None:
    try:
        payload = work()
    except (JdlibError, sa.exc.SQLAlchemyError) as exc:
        _fail(exc)
    _emit(payload, as_json)


def _run(coro: Coroutine[Any, Any, Payload], as_json: bool) -> None:
    try:
        payload = asyncio.run(coro)
    except (JdlibError, sa.exc.SQLAlchemyError) as exc:
        _fail(exc)
    _emit(payload, as_json)


async def _create_tenant(
    database_url: str,
    slug: str,
    name: str,
    strategy: PlacementStrategy,
    target_handle: str,
    region: str | None,
    shared_schema: str,
) -> Payload:
    engine = _engine(database_url)
    try:
        registry = _registry(engine, database_url, shared_schema)
        tenant = await registry.create(
            slug=slug,
            name=name,
            strategy=strategy,
            target_handle=target_handle,
            region=region,
        )
    finally:
        await engine.dispose()
    return {"id": str(tenant.id), "slug": tenant.slug, "status": tenant.status}


async def _list_tenants(database_url: str) -> Payload:
    engine = _engine(database_url)
    try:
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        async with session_factory() as session:
            rows = (
                await session.execute(
                    sa.select(Tenant, TenantPlacement)
                    .join(TenantPlacement, TenantPlacement.tenant_id == Tenant.id)
                    .order_by(Tenant.slug)
                )
            ).all()
    finally:
        await engine.dispose()
    return [
        {
            "id": str(tenant.id),
            "slug": tenant.slug,
            "status": tenant.status,
            "strategy": placement.strategy,
            "target_handle": placement.target_handle,
        }
        for tenant, placement in rows
    ]


async def _provision_tenant(
    database_url: str, tenant_id: uuid.UUID, shared_schema: str
) -> Payload:
    engine = _engine(database_url)
    try:
        registry = _registry(engine, database_url, shared_schema)
        tenant = await registry.provision(tenant_id)
    finally:
        await engine.dispose()
    return {"id": str(tenant.id), "slug": tenant.slug, "status": tenant.status}


async def _upgrade_tenants(database_url: str, shared_schema: str) -> Payload:
    engine = _engine(database_url)
    try:
        registry = _registry(engine, database_url, shared_schema)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        async with session_factory() as session:
            tenant_ids = list((await session.execute(sa.select(Tenant.id))).scalars().all())
        upgraded: list[Mapping[str, object]] = []
        for tenant_id in tenant_ids:
            tenant = await registry.migrate(tenant_id)
            upgraded.append({"id": str(tenant.id), "slug": tenant.slug, "status": "upgraded"})
        return upgraded
    finally:
        await engine.dispose()


async def _install_rls(database_url: str, schema: str, app_role: str) -> Payload:
    _import_framework_models()
    engine = _bound_engine(database_url, schema)
    try:
        await install_rls(engine, metadata=TenantBase.metadata, app_role=app_role)
    finally:
        await engine.dispose()
    return {"schema": schema, "app_role": app_role, "status": "installed"}


async def _verify_rls(database_url: str, schema: str, app_role: str) -> Payload:
    _import_framework_models()
    engine = _bound_engine(database_url, schema)
    try:
        await verify_rls(engine, app_role, metadata=TenantBase.metadata)
    finally:
        await engine.dispose()
    return {"schema": schema, "app_role": app_role, "status": "verified"}


@tenant_app.command("create")
def tenant_create(
    slug: Annotated[str, typer.Option("--slug")],
    name: Annotated[str, typer.Option("--name")],
    database_url: DatabaseUrl = None,
    strategy: Annotated[PlacementStrategy, typer.Option("--strategy")] = PlacementStrategy.SHARED,
    target_handle: Annotated[str, typer.Option("--target-handle")] = "default",
    region: Annotated[str | None, typer.Option("--region")] = None,
    shared_schema: SharedSchema = "public",
    json_output: JsonOutput = False,
) -> None:
    """Create a tenant record in the control plane."""
    url = _require_url(database_url)
    _run(
        _create_tenant(url, slug, name, strategy, target_handle, region, shared_schema),
        json_output,
    )


@tenant_app.command("provision")
def tenant_provision(
    tenant_id: Annotated[uuid.UUID, typer.Argument()],
    database_url: DatabaseUrl = None,
    shared_schema: SharedSchema = "public",
    json_output: JsonOutput = False,
) -> None:
    """Provision a tenant's plane and run its migrations."""
    url = _require_url(database_url)
    _run(_provision_tenant(url, tenant_id, shared_schema), json_output)


@tenant_app.command("list")
def tenant_list(
    database_url: DatabaseUrl = None,
    json_output: JsonOutput = False,
) -> None:
    """List tenants with their placements."""
    url = _require_url(database_url)
    _run(_list_tenants(url), json_output)


@db_app.command("upgrade-control")
def db_upgrade_control(
    database_url: DatabaseUrl = None,
    json_output: JsonOutput = False,
) -> None:
    """Upgrade the control plane to the head revision."""
    url = _require_url(database_url)

    def work() -> Payload:
        MigrationRunner(url).upgrade_control()
        return {"plane": "control", "status": "upgraded"}

    _run_sync(work, json_output)


@db_app.command("upgrade-tenants")
def db_upgrade_tenants(
    database_url: DatabaseUrl = None,
    shared_schema: SharedSchema = "public",
    json_output: JsonOutput = False,
) -> None:
    """Upgrade every registered tenant to its desired revision."""
    url = _require_url(database_url)
    _run(_upgrade_tenants(url, shared_schema), json_output)


@rls_app.command("install")
def rls_install(
    schema: Annotated[str, typer.Option("--schema")],
    app_role: Annotated[str, typer.Option("--app-role")],
    database_url: DatabaseUrl = None,
    json_output: JsonOutput = False,
) -> None:
    """Install and verify tenant isolation policies on one schema."""
    url = _require_url(database_url)
    _run(_install_rls(url, schema, app_role), json_output)


@rls_app.command("verify")
def rls_verify(
    schema: Annotated[str, typer.Option("--schema")],
    app_role: Annotated[str, typer.Option("--app-role")],
    database_url: DatabaseUrl = None,
    json_output: JsonOutput = False,
) -> None:
    """Verify tenant isolation policies on one schema."""
    url = _require_url(database_url)
    _run(_verify_rls(url, schema, app_role), json_output)


@schema_app.command("lint")
def schema_lint(
    rls: Annotated[bool, typer.Option("--rls/--no-rls")] = False,
    json_output: JsonOutput = False,
) -> None:
    """Lint the framework control and tenant metadata."""
    _import_framework_models()
    issues = lint_metadata([ControlBase.metadata, TenantBase.metadata], rls_enabled=rls)
    if issues:
        for issue in issues:
            typer.echo(f"{issue.rule} {issue.table}: {issue.message}", err=True)
        raise typer.Exit(1)
    _emit({"status": "clean", "issues": 0}, json_output)
