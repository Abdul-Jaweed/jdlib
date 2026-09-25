"""The enterprise application, composed -- and nothing here decides anything.

Every security decision this file appears to make is a choice of *collaborator*: which policy
engine answers, which directory supplies roles, which sink keeps the trail. The mechanisms are the
library's, and the layers under `app/` exist so a reader can see where each one is plugged in.

Two ASGI applications, deliberately, exactly as in the minimal example: the ops routes answer
without credentials (a liveness probe that needs a token fails during an identity-provider outage
and gets the process restarted for it), and the tenant plane is mounted under `/api`, where nothing
is reachable without a verified principal and a resolved tenant.
"""

from __future__ import annotations

from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from examples.enterprise.app.api.router import router as tenant_router
from examples.enterprise.app.configuration.settings import ExampleSettings
from examples.enterprise.app.dsn import async_dsn, control_dsn
from examples.enterprise.app.security.audit import DatabaseSecuritySink
from examples.enterprise.app.security.authentication import build_principal_provider
from examples.enterprise.app.security.authorization import CerbosEnforcer, build_pep
from examples.enterprise.app.security.container import build_container
from examples.enterprise.app.security.context import build_context_factory
from examples.enterprise.app.security.roles import RoleDirectory
from jdlib.authz.reader import ControlAccessReader
from jdlib.config import TenancyConfig
from jdlib.control.audit import DatabaseAuditSink
from jdlib.control.enums import PlacementStrategy
from jdlib.control.registry import TenantRegistry
from jdlib.integrations.fastapi import install, install_error_envelope
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.strategies.shared import SharedSchemaStrategy
from jdlib.tenancy.resolution import build_chain

#: Where the tenant-scoped application is mounted. Everything under it needs a principal and a
#: tenant; nothing outside it does.
API_PREFIX = "/api"


def create_app() -> FastAPI:
    """Build the application. Raises at startup when the environment is incomplete."""
    settings = ExampleSettings()  # type: ignore[call-arg]  # env-filled
    config = TenancyConfig()  # type: ignore[call-arg]  # pydantic-settings fills `context` from env

    engine = create_async_engine(async_dsn(control_dsn(config)))
    control_sessions = async_sessionmaker(engine, expire_on_commit=False)

    # The audit trail: one writer for the platform's rows, and the sink that gives security events
    # their action names. Both are the library's; the join between them is this application's.
    audit = DatabaseAuditSink(control_sessions)
    security_sink = DatabaseSecuritySink(audit=audit)

    reader = ControlAccessReader(control_sessions)
    registry = TenantRegistry(
        session_factory=control_sessions,
        strategies={PlacementStrategy.SHARED: SharedSchemaStrategy(engine, "public")},
        runner=MigrationRunner(control_dsn(config)),
        audit=audit,
    )

    # Authorization: Cerbos answers, the library's guard asks, and `CerbosEnforcer` bridges them.
    roles = RoleDirectory(reader=reader, session_factory=control_sessions)
    enforcer = CerbosEnforcer(pep=build_pep(settings, security_sink), roles=roles)
    container = build_container(session_factory=control_sessions, enforcer=enforcer)

    tenant_app = FastAPI(title=f"{settings.service_name} (tenant plane)")
    install(
        tenant_app,
        factory=build_context_factory(
            config=config,
            reader=reader,
            registry=registry,
            audit=audit,
            session_factory=control_sessions,
        ),
        chain=build_chain(config.resolvers),
        principal_provider=build_principal_provider(
            config=config, session_factory=control_sessions, audit=audit
        ),
        container=container,
    )
    tenant_app.include_router(tenant_router)

    outer = FastAPI(title=settings.service_name)
    install_error_envelope(outer)
    outer.mount(API_PREFIX, tenant_app)

    @outer.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness: the process is serving. Nothing about dependencies -- that is readiness."""
        return {"status": "ok"}

    @outer.get("/readyz")
    async def readyz() -> dict[str, str]:
        """Readiness: this process can serve right now.

        The database check is here and the policy engine's is not yet: a probe query needs a
        resource kind the policy set defines, and that set arrives with the Cerbos policies. Until
        then this probe reports what it can actually prove rather than a status it has not checked.
        """
        async with control_sessions() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "ready"}

    return outer
