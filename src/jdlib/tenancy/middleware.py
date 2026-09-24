from __future__ import annotations

import json
import re
import uuid
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Protocol
from urllib.parse import parse_qs

from jdlib.context import ContextFactory, Principal, context_scope
from jdlib.errors import (
    AuthenticationError,
    AuthenticationUnavailable,
    AuthorizationError,
    AuthorizationUnavailable,
    CrossTenantReferenceError,
    InvalidReference,
    JdlibError,
    TenantAccessDenied,
    TenantNotFound,
    TenantNotWritable,
    TenantSuspended,
)
from jdlib.tenancy.resolution import RequestInfo, ResolverChain

ASGIApp = Callable[..., Awaitable[None]]

# The order matters: a more specific class must precede the class it inherits
# from, or the general entry shadows it. ``AuthorizationUnavailable`` is an
# ``AuthorizationError`` and is listed first for exactly that reason - a decision
# that could not be taken is an outage (503), not a refusal (403), and collapsing
# the two tells a caller with a denied request that they were denied when the
# engine was simply unreachable. ``AuthenticationUnavailable`` is an
# ``AuthenticationError`` and is listed first for the same reason: an identity
# provider that could not be reached is an outage (503), never a rejection (401).
_STATUS_MAP: tuple[tuple[type[JdlibError], int], ...] = (
    (AuthenticationUnavailable, 503),
    (AuthenticationError, 401),
    (AuthorizationUnavailable, 503),
    (AuthorizationError, 403),
    (TenantNotFound, 404),
    (TenantAccessDenied, 404),
    (TenantSuspended, 423),
    (TenantNotWritable, 423),
    (CrossTenantReferenceError, 409),
    (InvalidReference, 409),
)


def http_status_for(exc: JdlibError) -> int:
    for error_type, status in _STATUS_MAP:
        if isinstance(exc, error_type):
            return status
    return 500


class PrincipalProvider(Protocol):
    async def __call__(self, request: RequestInfo) -> Principal | None: ...


def _request_info(scope: Mapping[str, Any]) -> RequestInfo:
    headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in scope.get("headers", [])
    }
    query = {
        key: values[-1] for key, values in parse_qs(
            scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True
        ).items()
    }
    return RequestInfo(
        headers=headers,
        query=query,
        path=scope.get("path", "/"),
        host=headers.get("host", ""),
        claims={},
    )


def _request_ids(headers: Mapping[str, str]) -> tuple[str, str, str | None]:
    request_id = uuid.uuid4().hex
    correlation_id = headers.get("x-correlation-id", request_id)
    trace_id: str | None = None
    traceparent = headers.get("traceparent")
    if traceparent:
        parts = traceparent.split("-")
        if len(parts) >= 4 and re.fullmatch(r"[0-9a-f]{32}", parts[1]):
            trace_id = parts[1]
    return request_id, correlation_id, trace_id


async def _send_error(send: Callable[..., Awaitable[None]], exc: JdlibError) -> None:
    status = http_status_for(exc)
    body = json.dumps({"error": type(exc).__name__, "detail": str(exc)}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class TenantMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        factory: ContextFactory,
        chain: ResolverChain,
        principal_provider: PrincipalProvider,
    ) -> None:
        self.app = app
        self._factory = factory
        self._chain = chain
        self._principal_provider = principal_provider

    async def __call__(self, scope: Mapping[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = _request_info(scope)
        try:
            principal = await self._principal_provider(request)
            if principal is None:
                raise AuthenticationError("no credentials presented")
            tenant_ref = await self._chain.resolve(request, principal)
            if tenant_ref is None:
                raise TenantNotFound("tenant could not be resolved")
            request_id, correlation_id, trace_id = _request_ids(request.headers)
            context = await self._factory.for_principal(
                principal,
                tenant_ref,
                request_id=request_id,
                correlation_id=correlation_id,
                trace_id=trace_id,
            )
        except JdlibError as exc:
            await _send_error(send, exc)
            return
        with context_scope(context):
            await self.app(scope, receive, send)
