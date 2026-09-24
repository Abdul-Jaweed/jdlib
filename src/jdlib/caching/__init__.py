"""Scoped caching (successor Phase 3).

The properties this namespace exists to guarantee, in the order they matter: a credential
object cannot be stored in a shared cache at all (ADR-2); a key cannot be built without the
tenant scope it needs; and invalidation is always scoped to a namespace or a tenant, never
global. Time is injected, so expiry behaviour is testable without sleeping.
"""

from jdlib.caching.errors import (
    CacheKeyError,
    CachePolicyError,
    CredentialCacheRefusedError,
)
from jdlib.caching.keys import SCHEMA_VERSION, ScopedKeyFactory
from jdlib.caching.local import LocalCache, contains_credential
from jdlib.caching.policy import CachePolicy
from jdlib.caching.protocol import CacheProvider

__all__ = [
    "SCHEMA_VERSION",
    "CacheKeyError",
    "CachePolicy",
    "CachePolicyError",
    "CacheProvider",
    "CredentialCacheRefusedError",
    "LocalCache",
    "ScopedKeyFactory",
    "contains_credential",
]
