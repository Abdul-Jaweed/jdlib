from __future__ import annotations

from typing import Final

from jdlib.caching.errors import CacheKeyError

SCHEMA_VERSION: Final = "v1"
SEPARATOR: Final = ":"
GLOBAL_SCOPE: Final = "_global"


class ScopedKeyFactory:
    """The only place a cache key is built, so tenant scope cannot be forgotten.

    Shape: ``jdlib:v1:{tenant}:{namespace}:{resource}:{identifier}``. Every component is
    validated rather than interpolated: empty parts and parts containing the separator are
    refused, because the archived cache concatenated fields with no delimiter at all and two
    different tenants could therefore share one entry.
    """

    def build(self, *, tenant: str, namespace: str, resource: str, identifier: str) -> str:
        self._check("tenant", tenant)
        self._check("namespace", namespace)
        self._check("resource", resource)
        self._check("identifier", identifier)
        if tenant == GLOBAL_SCOPE:
            raise CacheKeyError(
                f"namespace {namespace}: {GLOBAL_SCOPE!r} is reserved for global keys; "
                "use build_global"
            )
        return SEPARATOR.join(("jdlib", SCHEMA_VERSION, tenant, namespace, resource, identifier))

    def build_global(self, *, namespace: str, identifier: str) -> str:
        """For genuinely tenant-independent entries (a permission catalog, say)."""
        self._check("namespace", namespace)
        self._check("identifier", identifier)
        return SEPARATOR.join(("jdlib", SCHEMA_VERSION, GLOBAL_SCOPE, namespace, identifier))

    def tenant_prefix(self, tenant: str) -> str:
        self._check("tenant", tenant)
        return SEPARATOR.join(("jdlib", SCHEMA_VERSION, tenant, ""))

    def namespace_prefix(self, *, tenant: str, namespace: str) -> str:
        """Every key of one namespace within one tenant. Invalidation is scoped, never global.

        Built here rather than by the caller so the key shape has exactly one owner - and so
        that a prefix cannot be assembled from empty parts, which ``build`` refuses.
        """
        self._check("tenant", tenant)
        self._check("namespace", namespace)
        return SEPARATOR.join(("jdlib", SCHEMA_VERSION, tenant, namespace, ""))

    @staticmethod
    def _check(part: str, value: str) -> None:
        if not value:
            raise CacheKeyError(f"cache key part {part!r} must not be empty")
        if SEPARATOR in value:
            raise CacheKeyError(
                f"cache key part {part!r} must not contain the separator {SEPARATOR!r}: "
                "it would let two different entries collide"
            )
