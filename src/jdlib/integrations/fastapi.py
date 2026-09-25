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
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse, Response

from jdlib.authz.guards import Enforcer, tenant_target
from jdlib.authz.scopes import Target
from jdlib.context import ContextFactory, TenantContext, current_tenant
from jdlib.data.errors import ConnectorError
from jdlib.errors import JdlibError
from jdlib.persistence.uow import UnitOfWork
from jdlib.reliability import RetryBudgetExhaustedError, ShutdownInProgressError
from jdlib.security.context import RequestIds
from jdlib.security.errors import SecurityClassification, SecurityCode, SecurityDescriptor
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

    #: The requirement this dependency enforces, readable by whoever walks an application's own
    #: routes: `get_context` and `require(...)` both live in this module, so "the dependency came
    #: from jdlib" cannot tell a guarded route from an unguarded one. Set on the callable rather
    #: than wrapped in an object, because FastAPI holds the callable itself.
    setattr(dependency, "jdlib_permission", permission)  # noqa: B010 - a function attribute
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
    # The driver's own refusal, which arrives *unwrapped*: SQLAlchemy wraps a failure inside a
    # statement, but a pool connect the database refuses surfaces as the driver's `OSError`
    # (`ConnectionRefusedError` for asyncpg, whose async path this library's consumers run on).
    # Without this row a database that is *down* -- the exact case a readiness probe exists for --
    # is answered by an unhandled 500, while the same outage over psycopg is a 503.
    (ConnectionError, DEPENDENCY_UNAVAILABLE_DESCRIPTOR),
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
    app.add_exception_handler(HTTPException, _handle_http_exception)
    for error_type, descriptor in _CAPABILITY_DESCRIPTORS:
        app.add_exception_handler(error_type, _descriptor_handler(descriptor))
    app.add_exception_handler(Exception, _handle_unexpected)


#: `fastapi.HTTPException` is an application's own decision ("this name is taken", "no such
#: project") and Starlette answers it in a shape of its own: `{"detail": ...}`, no code, no
#: ids. Registering it here is what makes "one envelope" true rather than aspirational - an
#: application that raises one still answers the documented contract. Well-known statuses get
#: the code that names the condition; anything unmapped falls back to the status class, and a
#: 5xx is still generic.
_HTTP_STATUS_DESCRIPTORS: dict[int, SecurityDescriptor] = {
    400: SecurityDescriptor(
        SecurityCode.BAD_REQUEST, 400, False, SecurityClassification.VALIDATION
    ),
    401: SecurityDescriptor(
        SecurityCode.AUTHENTICATION_REQUIRED, 401, False, SecurityClassification.AUTHENTICATION
    ),
    403: SecurityDescriptor(
        SecurityCode.PERMISSION_DENIED, 403, False, SecurityClassification.AUTHORIZATION
    ),
    404: SecurityDescriptor(
        SecurityCode.NOT_FOUND, 404, False, SecurityClassification.DATA_BOUNDARY
    ),
    409: SecurityDescriptor(
        SecurityCode.CONFLICT, 409, False, SecurityClassification.DATA_BOUNDARY
    ),
    422: SecurityDescriptor(
        SecurityCode.VALIDATION_FAILED, 422, False, SecurityClassification.VALIDATION
    ),
    429: SecurityDescriptor(
        SecurityCode.TOO_MANY_REQUESTS, 429, True, SecurityClassification.AVAILABILITY
    ),
    503: DEPENDENCY_UNAVAILABLE_DESCRIPTOR,
}

#: The only response headers passed through from an application's own error: both are defined
#: for the client to act on, and both are the response's, not the server's, business.
_PASSTHROUGH_HEADERS = ("www-authenticate", "retry-after")


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


async def _handle_http_exception(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, HTTPException):
        raise exc
    descriptor = _HTTP_STATUS_DESCRIPTORS.get(exc.status_code)
    envelope = error_response(
        exc,
        request_ids=_ids_for(request),
        descriptor=descriptor,
        # The status is the application's, whether or not it is in the table above.
        status=exc.status_code,
        message=exc.detail if descriptor is not None else None,
    )
    carried = {
        name: value
        for name, value in (exc.headers or {}).items()
        if name.lower() in _PASSTHROUGH_HEADERS
    }
    return _envelope(
        ErrorResponse(
            status=envelope.status,
            payload=envelope.payload,
            headers={**dict(envelope.headers), **carried},
        )
    )


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
