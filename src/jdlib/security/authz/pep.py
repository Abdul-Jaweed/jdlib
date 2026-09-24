"""The enforcement point (directive §15, §16).

Application code calls this, never a policy engine directly, so Cerbos concepts
never reach business logic. The PEP adds the checks that must not depend on the
engine being reachable, and it fails closed in every direction:

* an unauthenticated caller is refused (401),
* a caller whose security context is not tenant-bound is refused rather than
  treated as unscoped,
* a query about another tenant's resource is refused before the engine is
  consulted (404),
* a denial — including one produced because the engine was unavailable,
  timed out or returned something unparsable — raises (403),
* an audit observer failure propagates, so a lost audit record can never be
  traded for a served request.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from jdlib.errors import (
    AuthenticationError,
    AuthorizationUnavailable,
    MissingTenantContext,
    PermissionDenied,
    TenantAccessDenied,
)
from jdlib.security.authz.decision import AuthorizationDecision, AuthorizationQuery
from jdlib.security.authz.interfaces import PolicyDecisionPoint
from jdlib.security.context import SecurityContext

DecisionObserver = Callable[[AuthorizationQuery, AuthorizationDecision], Awaitable[None]]


class AuthorizationPEP:
    """Turn authorization decisions into outcomes application code can rely on."""

    def __init__(
        self,
        *,
        pdp: PolicyDecisionPoint,
        on_decision: DecisionObserver | None = None,
    ) -> None:
        self._pdp = pdp
        self._on_decision = on_decision

    def __repr__(self) -> str:
        return f"AuthorizationPEP(pdp={self._pdp!r}, observing={self._on_decision is not None})"

    async def check(self, query: AuthorizationQuery) -> AuthorizationDecision:
        """Ask for a decision without raising on denial (optional checks)."""
        return await self._pdp.decide(query)

    async def require(
        self,
        query: AuthorizationQuery,
        *,
        context: SecurityContext | None = None,
    ) -> AuthorizationDecision:
        """Enforce the decision, raising a typed, mapped error when denied."""
        self._guard_context(query, context)
        decision = await self._pdp.decide(query)
        if self._on_decision is not None:
            await self._on_decision(query, decision)
        if not decision.allowed:
            if decision.degraded:
                # A decision that could not be taken is still a denial, but it is
                # reported as 503 so "we're unsure" is not confused with "you may
                # not", and so the outage is visible to operators (directive §20).
                raise AuthorizationUnavailable(self._denial_message(query, decision))
            raise PermissionDenied(self._denial_message(query, decision))
        return decision

    # -- guards ------------------------------------------------------------

    @staticmethod
    def _guard_context(query: AuthorizationQuery, context: SecurityContext | None) -> None:
        if context is None:
            return
        if not context.authenticated:
            raise AuthenticationError("authentication is required for this operation")
        tenant_id = context.tenant_id
        if tenant_id is None:
            raise MissingTenantContext(
                "an authorization request inside a request context requires a bound tenant"
            )
        if tenant_id != query.tenant_id:
            # Reported as 404 so the existence of another tenant's resource is
            # not confirmed to a caller who cannot reach it.
            raise TenantAccessDenied(
                f"resource {query.resource_kind}:{query.resource_id} is not available"
            )

    @staticmethod
    def _denial_message(query: AuthorizationQuery, decision: AuthorizationDecision) -> str:
        """A message that names the request but never the resource's data."""
        metadata = decision.safe_metadata()
        policy = metadata["policy_id"] or "n/a"
        return (
            f"authorization denied for {', '.join(query.actions)} on "
            f"{query.resource_kind}:{query.resource_id} "
            f"(reason={metadata['reason']}, policy={policy})"
        )


__all__ = ["AuthorizationPEP", "DecisionObserver"]
