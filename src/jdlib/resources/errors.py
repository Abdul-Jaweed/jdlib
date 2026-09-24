from __future__ import annotations

from jdlib.errors import JdlibError


class ResourceHydrationError(JdlibError):
    """A resource could not be hydrated, and nothing was substituted for it.

    Every refusal in this namespace raises this: no security context, a context without a
    tenant, a gate that says no, a handle with no resolvable credential, or a cached value
    that is not a connection configuration. There is deliberately no fallback - the design
    document is explicit that an unresolvable handle must never silently resolve to the
    shared target.
    """
