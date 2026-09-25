"""The smallest secure JDLib application.

Two ASGI applications, deliberately -- the convention the library's own consumer established:

* the **outer** one answers ``/healthz`` and ``/readyz`` without credentials. A liveness probe that
  needs a token fails during an identity-provider outage and gets the process restarted for it.
* the **inner** one, mounted at ``/api``, is where ``install`` puts the tenant middleware, so every
  route beneath it requires a verified principal and a resolved tenant. Nothing under ``/api`` is
  reachable without one.

Tenants are resolved in the order the operator configured (``JDLIB_RESOLVERS__ORDER``: a JWT claim,
a subdomain, a path segment, a header, an API key), because the chain comes from the library's own
``build_chain`` -- a hand-listed resolver here would silently ignore that configuration.

Every security decision in this file is a *choice about configuration* -- which resolver chain,
which placement strategy, which permissions exist -- and none of it is a mechanism this example
implements. The middleware, the guard, the tenant context and the error envelope come from
`jdlib.integrations.fastapi`, so the example's own code is the four routes at the bottom.

It also has **no configuration of its own**: everything comes from the library's own environment
contract (`JDLIB_*`, read by `TenancyConfig`), which is why there is no settings module here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from examples.minimal.app.dsn import async_dsn, control_dsn
from jdlib import (
    ContextFactory,
    TenancyConfig,
    TenantContext,
    UnitOfWork,
    current_tenant,
)
from jdlib.authn.wiring import (
    EntitlementAdapter,
    PrincipalDirectoryAdapter,
    TenantDirectoryAdapter,
    build_authenticator,
)
from jdlib.authz.guards import Enforcer
from jdlib.authz.pdp import Decision, DefaultPDP
from jdlib.authz.permissions import PermissionCatalog
from jdlib.authz.reader import ControlAccessReader
from jdlib.authz.resource_types import ResourceTypeRegistry
from jdlib.authz.scopes import ScopeResolver, Target
from jdlib.control.audit import DatabaseAuditSink, PrivilegeAuditAdapter
from jdlib.control.enums import PlacementStrategy
from jdlib.control.registry import RegistryWriteFence, TenantRegistry
from jdlib.integrations.fastapi import (
    JdlibContainer,
    get_context,
    install,
    install_error_envelope,
    require,
)
from jdlib.migrations.runner import MigrationRunner
from jdlib.persistence.strategies.shared import SharedSchemaStrategy
from jdlib.tenancy.resolution import build_chain

#: Where the tenant-scoped application is mounted. Everything under it needs a principal and a
#: tenant; nothing outside it does.
TENANT_PREFIX = "/api"


class RequestScopedEnforcer(Enforcer):
    """Builds a fresh PDP -- and so a fresh ``AuthzCache`` -- for every guard evaluation.

    A shared PDP would let one request's authorization answer be reused for another's, which is
    the kind of caching bug that only shows up under concurrency. This is the one piece of the
    wiring that exists for correctness rather than for configuration.
    """

    def __init__(self, pdp_factory: Callable[[], DefaultPDP]) -> None:
        self._pdp_factory = pdp_factory

    async def require(self, permission: str, target: Target, *, session: object) -> Decision:
        return await Enforcer(self._pdp_factory()).require(permission, target, session=session)


class OperatorAuthorizer:
    """The support-access gate the context factory asks before granting operator capabilities.

    Answering ``False`` is the safe default: no principal is an operator. Wire it to your own
    operator directory when the application needs support access, and keep that directory out of
    the tenant plane -- an operator is not a tenant member.
    """

    async def authorize(self, principal: object, capability: str) -> bool:
        return False


def _tenant_app(
    *,
    config: TenancyConfig,
    engine: AsyncEngine,
    control_sessions: async_sessionmaker[AsyncSession],
) -> FastAPI:
    """The tenant-scoped application: `install` puts the middleware and the envelope on it."""
    audit = DatabaseAuditSink(control_sessions)
    privilege_audit = PrivilegeAuditAdapter(audit)
    reader = ControlAccessReader(control_sessions)

    runner = MigrationRunner(control_dsn(config))
    registry = TenantRegistry(
        session_factory=control_sessions,
        strategies={PlacementStrategy.SHARED: SharedSchemaStrategy(engine, "public")},
        runner=runner,
        audit=audit,
    )
    catalog = PermissionCatalog.with_builtins()
    resource_types = ResourceTypeRegistry()

    def make_pdp() -> DefaultPDP:
        return DefaultPDP(catalog=catalog, reader=reader, scopes=ScopeResolver(resource_types))

    def uow_factory() -> UnitOfWork:
        context = current_tenant()
        fence = RegistryWriteFence(session_factory=control_sessions)
        return UnitOfWork(control_sessions, context, fence=fence)

    app = FastAPI(title="jdlib minimal example (tenant plane)")
    install(
        app,
        factory=ContextFactory(
            config=config.context,
            principals=PrincipalDirectoryAdapter(reader),
            tenants=TenantDirectoryAdapter(registry),
            servability=registry,
            entitlements=EntitlementAdapter(reader),
            operators=OperatorAuthorizer(),
            audit=privilege_audit,
        ),
        chain=build_chain(config.resolvers),
        principal_provider=build_authenticator(
            config, control_sessions, audit
        ).authenticate,
        container=JdlibContainer(
            session_factory=control_sessions,
            uow_factory=uow_factory,
            enforcer=RequestScopedEnforcer(make_pdp),
        ),
    )

    @app.get("/me", dependencies=[Depends(require("tenant:read"))])
    async def me(context: Annotated[TenantContext, Depends(get_context)]) -> dict[str, str]:
        """The caller's own tenant.

        Read from the context the middleware resolved -- never from a parameter, a path segment or
        a body. A caller who could name the tenant here could read another one's.
        """
        return {"tenant": context.tenant_slug}

    return app


def create_app() -> FastAPI:
    """Build the application. Raises at startup when the environment is incomplete."""
    config = TenancyConfig()  # type: ignore[call-arg]  # pydantic-settings fills `context` from JDLIB_CONTEXT__*
    engine = create_async_engine(async_dsn(control_dsn(config)))
    control_sessions = async_sessionmaker(engine, expire_on_commit=False)

    outer = FastAPI(title="jdlib minimal example")
    install_error_envelope(outer)  # the ops routes answer in the same envelope as everything else
    tenant_app = _tenant_app(config=config, engine=engine, control_sessions=control_sessions)
    outer.mount(TENANT_PREFIX, tenant_app)

    @outer.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness: the process is serving.

        It says nothing about the database or the identity provider -- that is readiness, and a
        liveness probe that fails on a dependency outage gets the process restarted for a problem
        a restart cannot fix.
        """
        return {"status": "ok"}

    @outer.get("/readyz")
    async def readyz() -> dict[str, str]:
        """Readiness: this process can serve right now.

        The connection failure is deliberately not caught. The library's envelope maps an
        unreachable database to ``503 DEPENDENCY_UNAVAILABLE``, and a readiness probe that
        answered "ready" while its database was down would be lying to the orchestrator.
        """
        async with control_sessions() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "ready"}

    return outer
