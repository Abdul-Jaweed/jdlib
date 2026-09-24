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

from jdlib.control.audit import DatabaseAuditSink
from jdlib.control.base import ControlBase
from jdlib.control.enums import PlacementStrategy
from jdlib.control.models import Tenant, TenantPlacement
from jdlib.control.registry import TenantRegistry
from jdlib.errors import JdlibError
from jdlib.lint import lint_metadata
from jdlib.migrations.runner import MigrationRunner
from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.rls import install_rls, verify_rls
from jdlib.persistence.strategies.schema import SchemaPerTenantStrategy
from jdlib.persistence.strategies.shared import SharedSchemaStrategy
from jdlib.security.compliance import (
    CONTROL_REGISTRY,
    MIGRATION_BRANCHES,
    ControlFramework,
    PostureOutcome,
    PostureReport,
    SecurityEvidence,
    collect_configuration_evidence,
    collect_migration_evidence,
    collect_policy_evidence,
    controls_for_framework,
    evaluate_posture,
    frameworks_in_use,
)
from jdlib.security.compliance.session import (
    collect_isolation_evidence,
    collect_schema_revision_evidence,
)
from jdlib.security.config import ComplianceConfig, Environment, SecurityConfig

Payload = Mapping[str, object] | list[Mapping[str, object]]

app = typer.Typer(no_args_is_help=True)
tenant_app = typer.Typer(no_args_is_help=True)
db_app = typer.Typer(no_args_is_help=True)
rls_app = typer.Typer(no_args_is_help=True)
schema_app = typer.Typer(no_args_is_help=True)
security_app = typer.Typer(no_args_is_help=True)
app.add_typer(tenant_app, name="tenant")
app.add_typer(db_app, name="db")
app.add_typer(rls_app, name="rls")
app.add_typer(schema_app, name="schema")
app.add_typer(security_app, name="security")

DatabaseUrl = Annotated[str | None, typer.Option("--database-url", envvar="JDLIB_CONTROL_DSN")]
SharedSchema = Annotated[str, typer.Option("--shared-schema")]
JsonOutput = Annotated[bool, typer.Option("--json")]
DeclaredEnvironment = Annotated[
    str | None,
    typer.Option("--environment", help="declared deployment profile"),
]
BoundSchema = Annotated[str | None, typer.Option("--schema", help="schema to bind the catalog to")]
MigrationBranch = Annotated[
    str, typer.Option("--branch", help="revision branch this schema carries")
]
PolicyDirectory = Annotated[str | None, typer.Option("--policy-directory")]
PdpKind = Annotated[str, typer.Option("--pdp-kind")]

_ASYNC_DRIVERS = {"postgresql", "postgresql+psycopg", "postgresql+psycopg2"}


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
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return TenantRegistry(
        session_factory=session_factory,
        strategies={
            PlacementStrategy.SHARED: SharedSchemaStrategy(engine, shared_schema),
            PlacementStrategy.SCHEMA: SchemaPerTenantStrategy(engine, runner),
        },
        runner=runner,
        audit=DatabaseAuditSink(session_factory),
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
    """Provision a tenant's plane and run its migrations.

    Shared and schema placements are registered by the CLI; a database
    placement needs the database strategy (with a SecretProvider) registered
    programmatically.
    """
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


# --- security posture, evidence and compliance (§9.5) ---------------------------


def _declared_config(environment: str | None) -> SecurityConfig:
    """The configuration to assess: the library defaults, or a declared profile.

    The CLI assesses the profile the operator declares. It cannot read a
    deployment's private settings, and it must not pretend to: every report says
    which profile it describes, and the configuration evidence records it.
    """
    if environment is None:
        return SecurityConfig()
    try:
        profile = Environment(environment)
    except ValueError as exc:
        known = ", ".join(item.value for item in Environment)
        raise typer.BadParameter(
            f"unknown environment: {environment}; expected one of {known}"
        ) from exc
    return SecurityConfig(compliance=ComplianceConfig(environment=profile))


def _expected_heads() -> dict[str, str]:
    """The head each branch should be at, from the checkout itself."""
    record = collect_migration_evidence()
    return {
        branch: str(record.observations[f"{branch}_head"]) for branch in MIGRATION_BRANCHES
    }


async def _live_evidence(
    url: str, schema: str, branch: str, environment: str | None
) -> list[SecurityEvidence]:
    """Observe a schema's catalog and the revision it has applied.

    The operator names the branch the schema carries; the collector records what it
    finds and whether it matches the head this checkout expects. There is no
    guessing about which schema is which.
    """
    _import_framework_models()
    heads = _expected_heads()
    if branch not in heads:
        raise typer.BadParameter(
            f"unknown branch: {branch}; expected one of {', '.join(MIGRATION_BRANCHES)}"
        )
    engine = _bound_engine(url, schema)
    try:
        return [
            await collect_isolation_evidence(engine, environment=environment),
            await collect_schema_revision_evidence(
                engine, branch=branch, expected_head=heads[branch], environment=environment
            ),
        ]
    finally:
        await engine.dispose()


async def _collect_evidence(
    config: SecurityConfig,
    *,
    database_url: str | None,
    schema: str | None,
    branch: str,
    policy_directory: str | None,
    pdp_kind: str,
    environment: str | None,
) -> list[SecurityEvidence]:
    records = [collect_configuration_evidence(config, environment=environment)]
    records.append(collect_migration_evidence(environment=environment))
    if policy_directory is not None:
        records.append(
            collect_policy_evidence(policy_directory, pdp_kind=pdp_kind, environment=environment)
        )
    if database_url is not None:
        if not schema:
            raise typer.BadParameter(
                "provide --schema with --database-url so the catalog can be bound"
            )
        records.extend(await _live_evidence(database_url, schema, branch, environment))
    return records


def _echo_posture(report: PostureReport) -> None:
    counts = report.counts
    typer.echo(
        f"profile={report.environment} outcome={report.worst_outcome.value} "
        f"ready={str(report.is_ready).lower()}"
    )
    typer.echo(
        " ".join(
            f"{outcome.value}={counts[outcome]}" for outcome in PostureOutcome if counts[outcome]
        )
    )
    for finding in report.findings:
        typer.echo(
            f"{finding.outcome.value.upper():<14} {finding.control_id:<14} "
            f"{finding.severity.value:<8} {finding.title}"
        )
        typer.echo(f"    {finding.reason}")


@security_app.command("posture")
def security_posture(
    environment: DeclaredEnvironment = None,
    database_url: DatabaseUrl = None,
    schema: BoundSchema = None,
    branch: MigrationBranch = "tenant",
    policy_directory: PolicyDirectory = None,
    pdp_kind: PdpKind = "cerbos",
    json_output: JsonOutput = False,
) -> None:
    """Report the posture of every technical control in the register.

    Exits non-zero when a control fails, so it can gate a pipeline. Readiness is
    what this reports; it is not a certification.
    """
    config = _declared_config(environment)
    records = asyncio.run(
        _collect_evidence(
            config,
            database_url=database_url,
            schema=schema,
            branch=branch,
            policy_directory=policy_directory,
            pdp_kind=pdp_kind,
            environment=environment,
        )
    )
    report = evaluate_posture(config, evidence=records, environment=environment)
    if json_output:
        _emit(report.as_dict(), json_output)
    else:
        _echo_posture(report)
    if not report.is_ready:
        raise typer.Exit(1)


@security_app.command("evidence")
def security_evidence(
    environment: DeclaredEnvironment = None,
    database_url: DatabaseUrl = None,
    schema: BoundSchema = None,
    branch: MigrationBranch = "tenant",
    policy_directory: PolicyDirectory = None,
    pdp_kind: PdpKind = "cerbos",
    json_output: JsonOutput = False,
) -> None:
    """Collect the evidence behind the posture report.

    Evidence is sanitized where it is built, so a credential cannot reach this
    output; policy bodies are never read, only counted and named.
    """
    config = _declared_config(environment)
    records = asyncio.run(
        _collect_evidence(
            config,
            database_url=database_url,
            schema=schema,
            branch=branch,
            policy_directory=policy_directory,
            pdp_kind=pdp_kind,
            environment=environment,
        )
    )
    if json_output:
        _emit([record.as_dict() for record in records], json_output)
        return
    for record in records:
        typer.echo(f"control={record.control_id} subject={record.subject}")
        typer.echo(f"    collected_at={record.collected_at.isoformat()} by={record.collected_by}")
        for key, value in record.observations.items():
            typer.echo(f"    {key}={value}")
        typer.echo(f"    reproduce: {record.reproducible}")


@security_app.command("compliance")
def security_compliance(
    framework: Annotated[str | None, typer.Option("--framework")] = None,
    environment: DeclaredEnvironment = None,
    json_output: JsonOutput = False,
) -> None:
    """List the technical controls this library implements and where they map.

    A mapping describes where a control belongs in a framework. It is not a
    certification, and JDLib does not make an installation compliant: these are
    technical controls and the evidence behind them.
    """
    if framework is not None:
        try:
            selected = ControlFramework(framework)
        except ValueError as exc:
            known = ", ".join(item.value for item in ControlFramework)
            raise typer.BadParameter(
                f"unknown framework: {framework}; expected one of {known}"
            ) from exc
        controls = controls_for_framework(selected)
    else:
        selected = None
        controls = tuple(CONTROL_REGISTRY[control_id] for control_id in sorted(CONTROL_REGISTRY))
    report = evaluate_posture(_declared_config(environment), environment=environment)
    counts = report.counts
    if json_output:
        _emit(
            {
                "controls": [
                    {
                        "control_id": control.control_id,
                        "title": control.title,
                        "category": control.category.value,
                        "implementation_status": control.implementation_status.value,
                        "verification_method": control.verification_method.value,
                        "mappings": [
                            {"framework": mapping.framework.value, "reference": mapping.reference}
                            for mapping in control.mappings
                        ],
                    }
                    for control in controls
                ],
                "frameworks": [item.value for item in frameworks_in_use()],
                "posture": report.as_dict(),
                "disclaimer": (
                    "Technical controls and evidence only: JDLib does not make an "
                    "installation certified or compliant."
                ),
            },
            json_output,
        )
        return
    typer.echo("JDLib technical security controls — readiness view, not a certification")
    if selected is not None:
        typer.echo(f"framework={selected.value} controls={len(controls)}")
    else:
        typer.echo("frameworks=" + ", ".join(item.value for item in frameworks_in_use()))
    for control in controls:
        mappings = ", ".join(
            f"{mapping.framework.value}:{mapping.reference}" for mapping in control.mappings
        )
        typer.echo(
            f"{control.control_id:<14} {control.implementation_status.value:<16} "
            f"{control.category.value:<18} {mappings}"
        )
    typer.echo(
        f"posture ({report.environment}): "
        + " ".join(
            f"{outcome.value}={counts[outcome]}" for outcome in PostureOutcome if counts[outcome]
        )
    )
    typer.echo(
        "Technical controls and evidence only: installing this library does not make an "
        "organisation certified or compliant."
    )
