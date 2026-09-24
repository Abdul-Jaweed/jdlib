"""Gateway integration layer (directive §18, §19; spec #12).

* :class:`NoGatewayAdapter` — no gateway; identity never comes from headers,
* :class:`KongGatewayAdapter` / :class:`TykGatewayAdapter` — verified identity
  assertions only (shared secret or HMAC),
* :class:`GatewayConfig` / :class:`GatewayMode` — the trust configuration.

Import safety (spec #74): no optional dependency and no HTTP client here; the
adapters verify what an already-parsed request carries.
"""

from jdlib.security.gateway.adapters import (
    KongGatewayAdapter,
    NoGatewayAdapter,
    TykGatewayAdapter,
)
from jdlib.security.gateway.config import GatewayConfig, GatewayMode

__all__ = [
    "GatewayConfig",
    "GatewayMode",
    "KongGatewayAdapter",
    "NoGatewayAdapter",
    "TykGatewayAdapter",
]
