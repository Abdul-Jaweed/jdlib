"""Ports of the authorization layer (directive §15, spec #35).

The port exists so application code depends on a capability, not on a vendor.
Two decision points exist in this repository and they are deliberately
different contracts:

* :class:`jdlib.authz.pdp.PolicyDecisionPoint` answers ``evaluate(principal,
  permission, target, context, session)`` from the tenant plane's own database
  (roles, bindings, grants) — the internal PDP,
* :class:`PolicyDecisionPoint` here answers ``decide(query)`` for an *external*
  policy engine (Cerbos today), in neutral product terms.

Keeping them apart is what stops Cerbos concepts from leaking into business
code: callers keep using permissions and resources they already understand.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from jdlib.security.authz.decision import AuthorizationDecision, AuthorizationQuery


@runtime_checkable
class PolicyDecisionPoint(Protocol):
    """An external policy engine that answers authorization queries."""

    async def decide(self, query: AuthorizationQuery) -> AuthorizationDecision: ...


__all__ = ["PolicyDecisionPoint"]
