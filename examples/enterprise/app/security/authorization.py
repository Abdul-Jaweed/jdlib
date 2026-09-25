"""Authorization: Cerbos answers, the library's route guard asks, and this module bridges them.

Two of the library's ports meet here, and neither knows about the other:

* `jdlib.security.authz` -- the security core -- asks a policy engine about an
  `AuthorizationQuery` and answers with an `AuthorizationDecision`;
* `jdlib.integrations.fastapi.require(...)` asks its container's `Enforcer` for
  `require(permission, target, *, session)`.

An application that wants **both** -- the library's guard on the route, and Cerbos as the engine
behind it -- owns the adapter between them. It is deliberately thin, and it keeps the one property
that matters: a decision the engine could not make stays a *degraded* decision, so the guard answers
503 rather than guessing. Nothing here decides anything; it translates.
"""

from __future__ import annotations

from examples.enterprise.app.configuration.settings import ExampleSettings
from examples.enterprise.app.security.roles import RoleDirectory
from jdlib.authz.pdp import Decision
from jdlib.authz.scopes import ScopeRef, Target
from jdlib.context import TenantContext, current_tenant
from jdlib.errors import PermissionDenied
from jdlib.security.audit.emitters import SecurityEventSink, authorization_audit_observer
from jdlib.security.audit.events import AuditSource
from jdlib.security.authz import AuthorizationPEP, CerbosPDP, CerbosTransport
from jdlib.security.authz.decision import AuthorizationQuery
from jdlib.security.authz.transports import HttpCerbosTransport


def build_pep(
    settings: ExampleSettings,
    sink: SecurityEventSink,
    *,
    transport: CerbosTransport | None = None,
) -> AuthorizationPEP:
    """The library's enforcement point, with Cerbos behind it and every decision observed.

    `on_decision` is what puts an authorization decision -- allow or deny -- into the audit trail.
    The observer is the library's, so the event's shape is the same one the HTTP edge and the MCP
    boundary emit.
    """
    pdp = CerbosPDP(
        config=settings.cerbos_config(),
        transport=transport or HttpCerbosTransport(timeout=settings.cerbos_config().timeout),
    )
    return AuthorizationPEP(
        pdp=pdp,
        on_decision=authorization_audit_observer(sink, source=AuditSource.API),
    )


def resource_for(target: Target) -> tuple[str, str]:
    """The `(kind, id)` this application asks about, for a route's `Target`.

    The mapping is the application's, so it is stated once, here, where the policy files can be read
    beside it -- `config/cerbos/policies/tenant_scope.yaml` is written against exactly these names.

    * a `ScopeRef` -- a tenant, an org, a team -- is the Cerbos resource kind `scope`, and the id is
      the scope's *name* (`ScopeType.TENANT` -> `"tenant"`), because a policy needs to distinguish
      a tenant scope from an org scope, not to name one tenant.
    * a `ResourceRef` keeps its own type as the kind, and its id.
    """
    if isinstance(target, ScopeRef):
        return "scope", target.type.value
    return target.resource_type, str(target.resource_id)


def query_for(
    permission: str,
    target: Target,
    *,
    context: TenantContext,
    roles: frozenset[str],
) -> AuthorizationQuery:
    """The question put to the policy engine, built from the guard's arguments and the context.

    The tenant in `attributes` is the **context's**, never a caller's argument: a route cannot ask
    about another tenant's scope, because it has no way to name one. The policy's cross-tenant rule
    (principal's tenant == resource's tenant) is then a second, independent check rather than the
    only one.
    """
    kind, identifier = resource_for(target)
    attributes: dict[str, object] = {"tenantId": str(context.tenant_id)}
    if isinstance(target, ScopeRef) and target.id is not None:
        attributes["scopeId"] = str(target.id)
    return AuthorizationQuery(
        principal_id=str(context.principal.id),
        tenant_id=context.tenant_id,
        resource_kind=kind,
        resource_id=identifier,
        actions=(permission,),
        roles=roles,
        attributes=attributes,
        principal_attributes={"tenantId": str(context.tenant_id)},
        request_id=context.request_id,
    )


class CerbosEnforcer:
    """The container's `enforcer`, in the shape `require(...)` expects."""

    def __init__(self, *, pep: AuthorizationPEP, roles: RoleDirectory) -> None:
        self._pep = pep
        self._roles = roles

    async def require(self, permission: str, target: Target, *, session: object) -> Decision:
        """Ask Cerbos. A denial raises `PermissionDenied`; an undecidable question raises too.

        The `session` the guard passes is not used: the roles this decision needs are read from the
        control plane by `RoleDirectory`, and the engine is asked over HTTP. It stays in the
        signature because that is the port `require(...)` calls through.
        """
        context = current_tenant()
        roles = await self._roles.names_for(context.principal, context.tenant_id)
        if not roles:
            # A role-less principal can be granted nothing by a role-based policy, and Cerbos
            # refuses to decide for one at all -- which the library reports as *degraded*, i.e. 503.
            # The caller is facing a denial, not an outage, so it is decided here and said plainly.
            raise PermissionDenied(f"{permission}: the caller has no roles in this tenant")
        query = query_for(permission, target, context=context, roles=roles)
        # No `context=` argument on `self._pep.require`: both surfaces bind the *tenant* context
        # this read comes from -- the HTTP middleware directly (`jdlib/tenancy/middleware.py`), the
        # MCP invocation beside its security context
        # (`jdlib/integrations/mcp/invocation.py`) -- so one enforcer serves both, and the check the
        # argument enables (the query's tenant must be the request's) is already structural:
        # `query_for` takes the tenant from `current_tenant()` and offers a caller no way to name
        # another.
        decision = await self._pep.require(query)
        # Reaching this line means the engine allowed it: `AuthorizationPEP.require` raises on a
        # denial and on a degraded decision, which is the whole reason to call it rather than
        # `check`.
        return Decision(True, decision.reason, ())
