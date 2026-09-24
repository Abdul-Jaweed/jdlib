from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from jdlib.caching.errors import CredentialCacheRefusedError
from jdlib.caching.keys import ScopedKeyFactory
from jdlib.caching.policy import CachePolicy
from jdlib.credentials.refs import ResolvedSecret, SecretRef


def contains_credential(value: object, *, _depth: int = 0) -> bool:
    """Whether a value is, or contains, a credential object.

    Recurses through the ordinary containers so that wrapping a secret in a dict is not a way
    around the guard. The limit is worth stating plainly: this refuses credential *objects*.
    A caller who has already flattened a secret into a plain string has defeated it by
    construction - which is exactly why ResolvedSecret is the only way to obtain one, and why
    its repr hides the value.
    """
    if isinstance(value, (SecretRef, ResolvedSecret)):
        return True
    if _depth > 8:
        return False
    if isinstance(value, Mapping):
        return any(
            contains_credential(k, _depth=_depth + 1) or contains_credential(v, _depth=_depth + 1)
            for k, v in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_credential(item, _depth=_depth + 1) for item in value)
    return False


@dataclass
class _Entry:
    value: Any
    expires_at: datetime


@dataclass
class LocalCache:
    """In-process cache. One instance per process; never a credential store (ADR-2).

    Time is injected so expiry is testable without sleeping. There is deliberately no flush:
    invalidation is always scoped to a namespace or a tenant, because a global clear is a
    cross-tenant event.
    """

    keys: ScopedKeyFactory
    clock: Callable[[], datetime]
    policy: CachePolicy = field(default_factory=CachePolicy)
    _entries: dict[str, _Entry] = field(default_factory=dict, repr=False)

    def set(
        self,
        *,
        tenant: str,
        namespace: str,
        resource: str,
        identifier: str,
        value: Any,
        ttl: int | None = None,
    ) -> None:
        if contains_credential(value):
            raise CredentialCacheRefusedError(
                f"namespace {namespace} refuses credential material: a shared cache must "
                "never hold a secret, at any lifetime. Resolve it at the point of use."
            )
        lifetime = self.policy.ttl_for(namespace, ttl)
        key = self.keys.build(
            tenant=tenant, namespace=namespace, resource=resource, identifier=identifier
        )
        self._entries[key] = _Entry(
            value=value, expires_at=self.clock() + timedelta(seconds=lifetime)
        )

    def get(self, *, tenant: str, namespace: str, resource: str, identifier: str) -> Any:
        key = self.keys.build(
            tenant=tenant, namespace=namespace, resource=resource, identifier=identifier
        )
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expires_at <= self.clock():
            del self._entries[key]
            return None
        return entry.value

    def invalidate_namespace(self, *, tenant: str, namespace: str) -> int:
        prefix = self.keys.namespace_prefix(tenant=tenant, namespace=namespace)
        doomed = [key for key in self._entries if key.startswith(prefix)]
        for key in doomed:
            del self._entries[key]
        return len(doomed)

    def invalidate_tenant(self, tenant: str) -> int:
        prefix = self.keys.tenant_prefix(tenant)
        doomed = [key for key in self._entries if key.startswith(prefix)]
        for key in doomed:
            del self._entries[key]
        return len(doomed)
