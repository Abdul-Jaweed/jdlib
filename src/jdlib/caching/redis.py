from __future__ import annotations

import json
from typing import Any, Final

from jdlib.caching.errors import (
    CacheSerializationError,
    CredentialCacheRefusedError,
)
from jdlib.caching.keys import ScopedKeyFactory
from jdlib.caching.local import contains_credential
from jdlib.caching.policy import CachePolicy

ENVELOPE_VERSION: Final = 1


class RedisCache:
    """Shared cache over real Redis.

    The client is imported lazily: ``import jdlib`` must not require the redis extra, but
    constructing this class does. Values travel as a JSON envelope with an explicit version,
    so a round trip is a property rather than a hope - and a value that cannot be serialised
    is refused at write time instead of being stored in a form no reader can parse.

    There is no flush. Invalidation is always scoped to a namespace or a tenant: the archived
    implementation fell back to FLUSHALL, which discards every tenant's entries at once.
    """

    def __init__(
        self,
        *,
        url: str,
        keys: ScopedKeyFactory,
        prefix: str = "jdlib",
        policy: CachePolicy | None = None,
    ) -> None:
        self.url = url
        self.keys = keys
        self.prefix = prefix
        self.policy = policy or CachePolicy()
        self._client: Any = None

    async def _connect(self) -> Any:
        if self._client is None:
            try:
                from redis.asyncio import Redis
            except ImportError as exc:  # pragma: no cover - depends on the extra
                raise RuntimeError(
                    "the Redis cache provider needs the 'redis' extra: pip install 'jdlib[redis]'"
                ) from exc
            self._client = Redis.from_url(self.url, decode_responses=True)
        return self._client

    async def raw_client(self) -> Any:
        """The underlying client, for diagnostics and for tests that must inspect the store."""
        return await self._connect()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _key(self, *, tenant: str, namespace: str, resource: str, identifier: str) -> str:
        scoped = self.keys.build(
            tenant=tenant, namespace=namespace, resource=resource, identifier=identifier
        )
        return f"{self.prefix}:{scoped}"

    async def set(
        self,
        *,
        tenant: str,
        namespace: str,
        resource: str,
        identifier: str,
        value: Any,
        ttl: int | None = None,
    ) -> None:
        # ADR-2 first, before the key is built and long before Redis is touched: the test
        # asserts that a refusal leaves the store byte-for-byte as it was.
        if contains_credential(value):
            raise CredentialCacheRefusedError(
                f"namespace {namespace} refuses credential material: a shared cache must "
                "never hold a secret, at any lifetime. Resolve it at the point of use."
            )
        lifetime = self.policy.ttl_for(namespace, ttl)
        try:
            payload = json.dumps({"v": ENVELOPE_VERSION, "value": value})
        except (TypeError, ValueError) as exc:
            raise CacheSerializationError(
                f"namespace {namespace}: a {type(value).__name__} cannot be cached, because it "
                "would be stored in a form no reader can parse"
            ) from exc
        client = await self._connect()
        await client.set(
            self._key(tenant=tenant, namespace=namespace, resource=resource, identifier=identifier),
            payload,
            ex=lifetime,
        )

    async def get(self, *, tenant: str, namespace: str, resource: str, identifier: str) -> Any:
        client = await self._connect()
        raw = await client.get(
            self._key(tenant=tenant, namespace=namespace, resource=resource, identifier=identifier)
        )
        if raw is None:
            return None
        try:
            envelope = json.loads(raw)
            if not isinstance(envelope, dict) or envelope.get("v") != ENVELOPE_VERSION:
                raise ValueError("not a cache envelope of this version")
            return envelope["value"]
        except (ValueError, KeyError, TypeError) as exc:
            raise CacheSerializationError(
                f"namespace {namespace}: the stored entry is not a v{ENVELOPE_VERSION} cache "
                "envelope; refusing to guess at its contents"
            ) from exc

    async def invalidate_namespace(self, *, tenant: str, namespace: str) -> int:
        return await self._drop(
            f"{self.prefix}:{self.keys.namespace_prefix(tenant=tenant, namespace=namespace)}"
        )

    async def invalidate_tenant(self, tenant: str) -> int:
        return await self._drop(f"{self.prefix}:{self.keys.tenant_prefix(tenant)}")

    async def _drop(self, prefix: str) -> int:
        client = await self._connect()
        doomed = [key async for key in client.scan_iter(match=f"{prefix}*")]
        if not doomed:
            return 0
        return int(await client.delete(*doomed))
