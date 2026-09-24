"""Authorization layer built on the security core (directive §15-#17).

* :mod:`jdlib.security.authz.decision` — neutral query and decision model,
* :class:`PolicyDecisionPoint` — the port an external engine satisfies,
* :class:`CerbosPDP` — the Cerbos adapter (fail-closed),
* :class:`AuthorizationPEP` — the enforcement point application code calls.

Import safety (spec #74): no optional dependency is imported here; the HTTP
transport for Cerbos lives in :mod:`jdlib.security.authz.transports`.
"""

from jdlib.security.authz.cerbos import CerbosConfig, CerbosPDP, CerbosTransport
from jdlib.security.authz.decision import (
    AuthorizationDecision,
    AuthorizationQuery,
    Effect,
)
from jdlib.security.authz.interfaces import PolicyDecisionPoint
from jdlib.security.authz.pep import AuthorizationPEP

__all__ = [
    "AuthorizationDecision",
    "AuthorizationPEP",
    "AuthorizationQuery",
    "CerbosConfig",
    "CerbosPDP",
    "CerbosTransport",
    "Effect",
    "PolicyDecisionPoint",
]
