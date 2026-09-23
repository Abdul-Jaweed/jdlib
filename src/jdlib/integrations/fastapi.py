"""FastAPI adapters for the jdlib request pipeline.

``require`` authorizes in its own unit of work: the guard opens
``container.uow_factory()``, so the ``RegistryWriteFence`` applies to guarded
reads too, and a guarded read during a relocation quiesce fails with 423
(``TenantNotWritable``). The handler's ``get_uow`` session is a different one
unless the caller shares it, so a permission revoked between the guard and the
handler is re-checked only when both use the same session.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass

from fastapi import FastAPI, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse, Response

from jdlib.authz.guards import Enforcer, tenant_target
from jdlib.authz.scopes import Target
from jdlib.context import ContextFactory, TenantContext, current_tenant
from jdlib.errors import JdlibError
from jdlib.persistence.uow import UnitOfWork
from jdlib.tenancy.middleware import PrincipalProvider, TenantMiddleware, http_status_for
from jdlib.tenancy.resolution import ResolverChain


@dataclass(frozen=True, slots=True)
class JdlibContainer:
    """Per-app collaborators the FastAPI dependencies read from ``app.state``."""

    session_factory: Callable[[], AsyncSession]
    uow_factory: Callable[[], UnitOfWork]
    enforcer: Enforcer


def install(
    app: FastAPI,
    *,
    factory: ContextFactory,
    chain: ResolverChain,
    principal_provider: PrincipalProvider,
    container: JdlibContainer | None = None,
) -> None:
    """Install tenant middleware, JdlibError handlers, and the app-state container."""
    if container is not None:
        app.state.jdlib_container = container
    app.add_middleware(
        TenantMiddleware,
        factory=factory,
        chain=chain,
        principal_provider=principal_provider,
    )
    app.add_exception_handler(JdlibError, _handle_jdlib_error)


async def get_context() -> TenantContext:
    """Return the tenant context resolved by ``TenantMiddleware`` for this request."""
    return current_tenant()


async def get_uow(request: Request) -> AsyncIterator[UnitOfWork]:
    """Yield the request-scoped ``UnitOfWork`` built by the app container."""
    yield _container(request).uow_factory()


def require(
    permission: str, target_factory: Callable[..., Target] | None = None
) -> Callable[[Request], Awaitable[None]]:
    """Return a dependency enforcing ``permission`` through the container's ``Enforcer``."""

    async def dependency(request: Request) -> None:
        container = _container(request)
        target: Target = tenant_target() if target_factory is None else target_factory(request)
        async with container.uow_factory() as session:
            await container.enforcer.require(permission, target, session=session)

    return dependency


def _container(request: Request) -> JdlibContainer:
    container: JdlibContainer | None = getattr(request.app.state, "jdlib_container", None)
    if container is None:
        raise RuntimeError("jdlib container is not installed on the app")
    return container


async def _handle_jdlib_error(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, JdlibError):
        raise exc
    return JSONResponse(
        status_code=http_status_for(exc),
        content={"error": type(exc).__name__, "detail": str(exc)},
    )
