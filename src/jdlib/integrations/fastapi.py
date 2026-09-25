"""FastAPI adapters for the jdlib request pipeline.

``require`` authorizes in its own unit of work: the guard opens
``container.uow_factory()``, so the ``RegistryWriteFence`` applies to guarded
reads too, and a guarded read during a relocation quiesce fails with 423
(``TenantNotWritable``). The guard authorizes once, in that transaction;
``get_uow`` opens a separate session for the handler (each ``UnitOfWork`` gets
a new one), so the guard's decision is not re-validated there: a permission
revoked after the check is observed only by a fresh evaluation in the
handler's own session, not by re-checking the guard's decision (a TOCTOU
window between the guard and the handler).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import InterfaceError as SqlAlchemyInterfaceError
from sqlalchemy.exc import OperationalError as SqlAlchemyOperationalError
from sqlalchemy.exc import TimeoutError as SqlAlchemyTimeoutError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse, Response

from jdlib.authz.guards import Enforcer, tenant_target
from jdlib.authz.scopes import Target
from jdlib.context import ContextFactory, TenantContext, current_tenant
from jdlib.data.errors import ConnectorError
from jdlib.errors import JdlibError
from jdlib.persistence.uow import UnitOfWork
from jdlib.reliability import RetryBudgetExhaustedError, ShutdownInProgressError
from jdlib.security.context import RequestIds
from jdlib.security.errors import SecurityDescriptor
from jdlib.security.responses import (
    DEPENDENCY_UNAVAILABLE_DESCRIPTOR,
    ErrorResponse,
    error_response,
    validation_failed_response,
)
from jdlib.security.tracing import request_ids_from_headers
from jdlib.tenancy.middleware import PrincipalProvider, TenantMiddleware
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
    install_error_envelope(app)


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


#: Failures raised by capabilities that sit *above* `jdlib.security`: the core descriptor
#: table cannot name them (`jdlib.data` imports `jdlib.security`, so the reverse edge would be
#: a cycle). One mapping, here at the edge, with the canonical descriptor shape - rather than
#: each application inventing its own dependency-to-status table.
_CAPABILITY_DESCRIPTORS: tuple[tuple[type[Exception], SecurityDescriptor], ...] = (
    (ConnectorError, DEPENDENCY_UNAVAILABLE_DESCRIPTOR),
    (RetryBudgetExhaustedError, DEPENDENCY_UNAVAILABLE_DESCRIPTOR),
    (ShutdownInProgressError, DEPENDENCY_UNAVAILABLE_DESCRIPTOR),
    # The connection-level database errors, and only those: a connection the database refused
    # is the dependency being unavailable and deserves the 503 that invites a retry, while a
    # statement it *rejected* is a defect here and keeps the 500 that says so. Applications
    # used to carry this table themselves - one per application, in its own body shape, which
    # is how a documented contract drifts into three of them.
    (SqlAlchemyOperationalError, DEPENDENCY_UNAVAILABLE_DESCRIPTOR),
    (SqlAlchemyInterfaceError, DEPENDENCY_UNAVAILABLE_DESCRIPTOR),
    (SqlAlchemyTimeoutError, DEPENDENCY_UNAVAILABLE_DESCRIPTOR),
)


def install_error_envelope(app: FastAPI) -> None:
    """Answer every failure with the one documented envelope.

    Four registrations, one builder (`jdlib.security.responses`): every ``JdlibError``, the
    capability failures that module cannot name, a malformed request body, and a catch-all.
    The catch-all is the part that matters most: the handler this replaces sent the exception's
    own class name and text for *every* status, so a 5xx whose message named a DSN or an
    internal endpoint reached the client verbatim. `docs/security/error-responses.md` has
    always said a 5xx never echoes its own text.
    """
    app.add_exception_handler(JdlibError, _handle_jdlib_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    for error_type, descriptor in _CAPABILITY_DESCRIPTORS:
        app.add_exception_handler(error_type, _descriptor_handler(descriptor))
    app.add_exception_handler(Exception, _handle_unexpected)


def _ids_for(request: Request) -> RequestIds:
    """The ids this request is known by: the context's, or the headers' when there is none."""
    try:
        context = current_tenant()
    except JdlibError:
        return request_ids_from_headers(request.headers)
    return RequestIds(
        request_id=context.request_id,
        correlation_id=context.correlation_id,
        trace_id=context.trace_id,
    )


def _envelope(envelope: ErrorResponse) -> JSONResponse:
    return JSONResponse(
        status_code=envelope.status,
        content=dict(envelope.payload),
        headers=dict(envelope.headers),
    )


async def _handle_jdlib_error(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, JdlibError):
        raise exc
    return _envelope(error_response(exc, request_ids=_ids_for(request)))


async def _handle_validation_error(request: Request, exc: Exception) -> Response:
    """A malformed request is a 422 in the same envelope, never a 500 and never a stack trace."""
    return _envelope(validation_failed_response(request_ids=_ids_for(request)))


async def _handle_unexpected(request: Request, exc: Exception) -> Response:
    """A failure nobody classified: a generic 500. The detail stays in the logs."""
    return _envelope(error_response(exc, request_ids=_ids_for(request)))


def _descriptor_handler(
    descriptor: SecurityDescriptor,
) -> Callable[[Request, Exception], Awaitable[Response]]:
    async def handler(request: Request, exc: Exception) -> Response:
        return _envelope(
            error_response(exc, request_ids=_ids_for(request), descriptor=descriptor)
        )

    return handler
