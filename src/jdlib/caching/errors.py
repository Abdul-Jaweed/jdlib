from __future__ import annotations

from jdlib.errors import JdlibError


class CacheKeyError(JdlibError):
    """A cache key could not be built safely: missing scope, empty part, or a delimiter clash."""


class CachePolicyError(JdlibError):
    """A requested lifetime is outside what the policy for that namespace permits."""


class CacheSerializationError(JdlibError):
    """A value cannot survive the cache's serialisation, or a stored entry cannot be read back.

    Raised at write time for a value that would be stored unreadably - the archived cache
    wrote repr() values, which parse back into nothing, so those entries expired instead of
    being used. Raised at read time for an entry that is not a cache envelope.
    """


class CredentialCacheRefusedError(JdlibError):
    """A credential object was offered to a shared cache, and was refused.

    ADR-2. The refusal names the namespace so the caller knows where they tried to put it,
    and never the value - including its length or a prefix.
    """
