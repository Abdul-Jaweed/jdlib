"""The MCP security boundary: the HTTP edge's chain, run for a second surface (directive §19).

FastMCP is another external application surface, and the directive's requirement is that it must
not bypass the library: every MCP request establishes an authoritative `SecurityContext` from the
approved mechanism, and never from a `user_id`, a `tenant_id`, a `roles` list or an
`authenticated=true` that a client sent.

The way to be sure is not to reimplement the chain carefully — it is to *be* the chain. These are
the middleware's own five steps, given the same collaborators the HTTP installer is given: the
`PrincipalProvider` that reads the credential, the `ResolverChain` that decides the tenant, and
the `ContextFactory` that validates liveness, servability and entitlements before building the
context. Nothing here authenticates anything itself, and nothing here reads identity out of the
request beyond what the provider does with the credential it finds.

What a request *may* carry is its correlation id — that is what correlation means — while the
request id the audit rows are keyed by is always minted here, by the one function both edges call.
"""

from __future__ import annotations

from collections.abc import Callable

from jdlib.context import ContextFactory
from jdlib.errors import AuthenticationError, TenantNotFound
from jdlib.security.audit.emitter import SecurityEventEmitter, emit_safely
from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.context import (
    AuthMethod,
    RequestIds,
    SecurityContext,
    security_context_scope,
)
from jdlib.security.tracing import SecuritySpan, TracerLike, security_span
from jdlib.tenancy.middleware import PrincipalProvider, request_ids_for
from jdlib.tenancy.resolution import RequestInfo, ResolverChain


class McpSecurityBoundary:
    """Establishes the authoritative context for one MCP request.

    The boundary owns no policy of its own: it decides nothing the HTTP path does not decide, and
    refuses exactly what that path refuses — no principal, and no resolvable tenant.
    """

    def __init__(
        self,
        *,
        principal_provider: PrincipalProvider,
        chain: ResolverChain,
        factory: ContextFactory,
        tracer: TracerLike | None = None,
        emitter: SecurityEventEmitter | None = None,
        auth_method: Callable[[], AuthMethod] | None = None,
    ) -> None:
        self._principal_provider = principal_provider
        self._chain = chain
        self._factory = factory
        self._tracer = tracer
        self._emitter = emitter
        self._auth_method = auth_method

    def __repr__(self) -> str:
        return f"McpSecurityBoundary(chain={type(self._chain).__name__})"

    async def establish(self, *, request: RequestInfo) -> SecurityContext:
        """The context this request runs under, or the refusal that names why it may not.

        A malformed trace context does not fail the request — the library's W3C parser is strict
        and returns nothing rather than guessing a trace id — so it is the two refusals that
        follow that decide: no principal, and no resolvable tenant.
        """
        with security_span(
            self._tracer, "mcp.request", attributes={"security.operation": "mcp.request"}
        ) as span:
            request_ids = RequestIds(*request_ids_for(request.headers))
            principal = await self._principal_provider(request)
            if principal is None:
                self._refused(span, reason="no credentials presented")
                raise AuthenticationError("no credentials presented")
            tenant_ref = await self._chain.resolve(request, principal)
            if tenant_ref is None:
                self._refused(span, reason="tenant could not be resolved")
                raise TenantNotFound("tenant could not be resolved")
            tenant = await self._factory.for_principal(
                principal,
                tenant_ref,
                request_id=request_ids.request_id,
                correlation_id=request_ids.correlation_id,
                trace_id=request_ids.trace_id,
            )
            span.set_attribute("security.result", "ok")
            context = SecurityContext.from_tenant_context(
                tenant, auth_method=self._resolved_auth_method()
            )
            with security_context_scope(context):
                self._record(context)
            return context

    def _record(self, context: SecurityContext) -> None:
        """Record the established request while its own scope is in force.

        Emitted inside the scope on purpose: an event written one line before the scope arrives
        carries an empty actor, and a request record with no actor is not evidence.
        """
        emit_safely(
            self._emitter,
            SecurityAuditEvent(
                event_type=SecurityEventType.MCP_REQUEST,
                outcome=AuditOutcome.SUCCESS,
                action="mcp.request",
                source=AuditSource.API,
                resource_type="mcp-surface",
                metadata={"auth_method": str(context.auth_method)},
            ),
        )

    def _resolved_auth_method(self) -> AuthMethod:
        """How this request was authenticated, as far as the library can know.

        A surface that authenticates more than one way records the method the way the HTTP
        application does — where the credential was accepted — and hands the reader in. Without
        one, the method is `SERVICE`: this is a service surface, and `NONE` would make a real
        authentication look anonymous.
        """
        if self._auth_method is None:
            return AuthMethod.SERVICE
        return self._auth_method()

    def _refused(self, span: SecuritySpan, *, reason: str) -> None:
        """Mark the span and keep the reason where a diagnosis can read it.

        The refusal travels to the caller as the canonical error; the reason stays on the span,
        which is the side of the boundary that may name internals.
        """
        span.set_attribute("security.result", "refused")
        span.set_attribute("security.reason", reason)
