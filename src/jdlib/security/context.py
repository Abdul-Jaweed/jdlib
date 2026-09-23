"""Request-scoped security context (spec #6, #34, #79).

Design notes
------------
``SecurityContext`` is the request-scoped *authentication* record. Tenancy
state stays owned by :class:`~jdlib.context.TenantContext`; a security context
that has resolved a tenant keeps a reference to it instead of copying
tenant_id, slug, strategy or privilege. Request/correlation/trace identifiers
are owned here because they must exist even for requests that never resolve a
tenant, and :meth:`SecurityContext.from_tenant_context` derives them from the
tenant context so the two records cannot diverge.

Fail-closed rules enforced by construction:

* constructing a context with an anonymous principal or ``AuthMethod.NONE``
  raises :class:`~jdlib.errors.AuthenticationError` — an unauthenticated
  context exists only through the explicit :meth:`SecurityContext.anonymous`
  factory,
* :func:`current_security_context` raises when no context is bound,
* :class:`TokenMetadata` has no field for raw credentials, so a JWT or API key
  cannot be smuggled into the context (and from there into logs, spans or audit
  events).
"""

from __future__ import annotations

import contextvars
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.errors import AuthenticationError, MissingTenantContext

_MAX_IDENTIFIER_LENGTH = 128


class AuthMethod(StrEnum):
    """How the current request was authenticated."""

    JWT = "jwt"
    API_KEY = "api_key"
    GATEWAY = "gateway"
    SERVICE = "service"
    TEST = "test"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class TokenMetadata:
    """Non-secret metadata about the credential used for authentication.

    Deliberately has no field for the raw token, API key or secret material.
    """

    issuer: str | None = None
    audience: str | None = None
    subject: str | None = None
    token_type: str | None = None
    jti: str | None = None
    expires_at: datetime | None = None
    scopes: frozenset[str] | None = None
    client_id: str | None = None


def _validate_identifier(value: object, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    if len(value) > _MAX_IDENTIFIER_LENGTH:
        raise ValueError(f"{field} must be at most {_MAX_IDENTIFIER_LENGTH} characters")
    if any(char < " " or char == "\x7f" for char in value):
        raise ValueError(f"{field} must not contain control characters")


@dataclass(frozen=True, slots=True)
class RequestIds:
    """Trusted request, correlation and trace identifiers for one request."""

    request_id: str
    correlation_id: str | None = None
    trace_id: str | None = None

    def __post_init__(self) -> None:
        _validate_identifier(self.request_id, "request_id")
        if self.correlation_id is None:
            object.__setattr__(self, "correlation_id", self.request_id)
        else:
            _validate_identifier(self.correlation_id, "correlation_id")
        if self.trace_id is not None:
            _validate_identifier(self.trace_id, "trace_id")


def new_request_ids() -> RequestIds:
    """Generate identifiers for a request that arrives without them."""
    return RequestIds(request_id=uuid.uuid4().hex)


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Immutable, request-scoped authentication and tenancy context."""

    principal: Principal
    request_ids: RequestIds
    auth_method: AuthMethod
    tenant: TenantContext | None = None
    token_metadata: TokenMetadata | None = None

    def __post_init__(self) -> None:
        if self.principal.kind is PrincipalKind.ANONYMOUS:
            raise AuthenticationError(
                "cannot build a security context for an anonymous principal; "
                "use SecurityContext.anonymous()"
            )
        if self.auth_method is AuthMethod.NONE:
            raise AuthenticationError(
                "cannot build a security context without an authentication method; "
                "use SecurityContext.anonymous()"
            )

    # -- Factories ----------------------------------------------------------

    @classmethod
    def anonymous(cls, *, request_ids: RequestIds | None = None) -> SecurityContext:
        """Build an explicit, unauthenticated context.

        This is the only way to obtain an unauthenticated context; it is
        deliberately verbose so it cannot happen by accident. Fail-closed
        checks (``current_security_context``, ``require_tenant``) treat it as
        unauthenticated.
        """
        context: SecurityContext = object.__new__(cls)
        anonymous = Principal(kind=PrincipalKind.ANONYMOUS, id=uuid.uuid4())
        object.__setattr__(context, "principal", anonymous)
        object.__setattr__(context, "request_ids", request_ids or new_request_ids())
        object.__setattr__(context, "auth_method", AuthMethod.NONE)
        object.__setattr__(context, "tenant", None)
        object.__setattr__(context, "token_metadata", None)
        return context

    @classmethod
    def from_tenant_context(
        cls,
        tenant: TenantContext,
        *,
        auth_method: AuthMethod,
        token_metadata: TokenMetadata | None = None,
    ) -> SecurityContext:
        """Promote a resolved tenant context into a security context.

        The principal, request identifiers and tenancy state are taken from
        ``tenant`` — nothing is duplicated or re-derived.
        """
        return cls(
            principal=tenant.principal,
            request_ids=RequestIds(
                request_id=tenant.request_id,
                correlation_id=tenant.correlation_id,
                trace_id=tenant.trace_id,
            ),
            auth_method=auth_method,
            tenant=tenant,
            token_metadata=token_metadata,
        )

    # -- Derived state ------------------------------------------------------

    @property
    def authenticated(self) -> bool:
        return (
            self.auth_method is not AuthMethod.NONE
            and self.principal.kind is not PrincipalKind.ANONYMOUS
        )

    @property
    def request_id(self) -> str:
        return self.request_ids.request_id

    @property
    def correlation_id(self) -> str:
        return self.request_ids.correlation_id or self.request_ids.request_id

    @property
    def trace_id(self) -> str | None:
        return self.request_ids.trace_id

    @property
    def tenant_id(self) -> uuid.UUID | None:
        return self.tenant.tenant_id if self.tenant is not None else None

    @property
    def privilege(self) -> object | None:
        return self.tenant.privilege if self.tenant is not None else None

    def require_tenant(self) -> TenantContext:
        """Return the resolved tenant context or fail closed."""
        if self.tenant is None:
            raise MissingTenantContext("no tenant is bound to the security context")
        return self.tenant


_SECURITY_CONTEXT: contextvars.ContextVar[SecurityContext | None] = contextvars.ContextVar(
    "jdlib_security_context", default=None
)


@contextmanager
def security_context_scope(context: SecurityContext) -> Iterator[SecurityContext]:
    """Bind ``context`` for the duration of the block."""
    token = _SECURITY_CONTEXT.set(context)
    try:
        yield context
    finally:
        _SECURITY_CONTEXT.reset(token)


def current_security_context_or_none() -> SecurityContext | None:
    """Return the bound security context, or ``None`` when absent."""
    return _SECURITY_CONTEXT.get()


def current_security_context() -> SecurityContext:
    """Return the bound security context, failing closed when absent."""
    context = _SECURITY_CONTEXT.get()
    if context is None:
        raise AuthenticationError("no security context is active")
    return context


__all__ = [
    "AuthMethod",
    "RequestIds",
    "SecurityContext",
    "TokenMetadata",
    "current_security_context",
    "current_security_context_or_none",
    "new_request_ids",
    "security_context_scope",
]
