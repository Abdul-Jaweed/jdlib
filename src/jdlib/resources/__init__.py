"""Resource hydration (successor Phase 4).

Implements the contract in ``docs/jdlib/05-tenant-lifecycle.md`` section 7: a handle is an
opaque name, resolution goes through the credential provider, and the result is cached
against the credential version so a rotation rebuilds rather than serving a stale target.
Lazy, deterministic, tenant-scoped, and never a fallback to a shared target.
"""

from jdlib.resources.connection import ConnectionConfig
from jdlib.resources.errors import ResourceHydrationError
from jdlib.resources.handle import ResourceHandle
from jdlib.resources.resolver import ResourceResolver

__all__ = [
    "ConnectionConfig",
    "ResourceHandle",
    "ResourceHydrationError",
    "ResourceResolver",
]
