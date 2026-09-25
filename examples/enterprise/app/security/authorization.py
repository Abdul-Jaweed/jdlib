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
from jdlib.authz.scopes import ResourceRef, ScopeRef, Target
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


def _resource_of(target: Target) -> tuple[str, str]:
    """The (kind, id) pair a Cerbos policy names.

    The mapping is this application's convention, and the policies in `config/cerbos/` are written
    to match it: a resource-scoped guard is its own kind with the resource's id, while a
    tenant-scoped one is the kind `scope` with the scope's name -- a scope is not a resource with an
    id, and pretending otherwise would put a made-up id in front of the engine.
    """
    if isinstance(target, ResourceRef):
        return target.resource_type, str(target.resource_id)
    return "scope", target.type.value


def _query(
    permission: str, target: Target, context: TenantContext, roles: frozenset[str]
) -> AuthorizationQuery:
    resource_kind, resource_id = _resource_of(target)
    attributes: dict[str, object] = {"tenantId": str(context.tenant_id)}
    if isinstance(target, ScopeRef) and target.id is not None:
        attributes["scopeId"] = str(target.id)
    return AuthorizationQuery(
        principal_id=str(context.principal.id),
        tenant_id=context.tenant_id,
        resource_kind=resource_kind,
        resource_id=resource_id,
        actions=(permission,),
        roles=roles,
        # The tenant guard in the policies compares the principal's tenant with the resource's, so
        # the resource has to carry one -- spelled the way the library spells the principal's, or
        # every request would deny.
        attributes=attributes,
        principal_attributes={"tenant_slug": context.tenant_slug},
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
        decision = await self._pep.require(_query(permission, target, context, roles))
        # Reaching this line means the engine allowed it: `AuthorizationPEP.require` raises on a
        # denial and on a degraded decision, which is the whole reason to call it rather than
        # `check`.
        return Decision(True, decision.reason, ())
