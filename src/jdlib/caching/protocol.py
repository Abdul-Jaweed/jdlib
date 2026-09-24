from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class CacheProvider(Protocol):
    """What a cache implementation must do. Local and shared providers share this shape."""

    def get(self, *, tenant: str, namespace: str, resource: str, identifier: str) -> Any: ...

    def set(
        self,
        *,
        tenant: str,
        namespace: str,
        resource: str,
        identifier: str,
        value: Any,
        ttl: int | None = None,
    ) -> None: ...

    def invalidate_namespace(self, *, tenant: str, namespace: str) -> int: ...

    def invalidate_tenant(self, tenant: str) -> int: ...
