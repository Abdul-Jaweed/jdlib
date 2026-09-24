"""Redis cache provider against a REAL Redis (successor Phase 3, the PARTIAL remainder).

The integration layer is the right home for this, and the point is the defect it must make
unreproducible: the archived cache serialised values with repr() - which cannot be parsed
back - so those entries were written successfully and missed forever. Here a value that
cannot survive the round trip is refused at write time instead.

No mocks. A fake Redis client would prove nothing about serialisation, TTL or SCAN, which is
exactly what this file exists to test.
"""

from __future__ import annotations

import asyncio

import pytest

# testcontainers.redis is deprecated, and the gate runs with -W error:
from testcontainers.community.redis import RedisContainer

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"


@pytest.fixture(scope="module")
def redis_url() -> str:
    with RedisContainer("redis:7-alpine") as container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"


@pytest.fixture()
async def cache(redis_url):
    from jdlib.caching.keys import ScopedKeyFactory
    from jdlib.caching.redis import RedisCache

    c = RedisCache(url=redis_url, keys=ScopedKeyFactory(), prefix="jdlib-test")
    # The container instance is this file's alone (a throwaway on a random port, not the
    # lab's Redis), so clearing its database is test hygiene, not a production shortcut -
    # RedisCache itself has no flush, and test_offers_no_global_flush asserts that.
    raw = await c.raw_client()
    await raw.flushdb()
    yield c
    await c.close()


async def test_a_dict_survives_a_real_round_trip(cache) -> None:
    """The defect: repr() values were stored and could never be read back."""
    payload = {"rows": [{"NAME": "acme", "ID": 7}], "count": 1}

    await cache.set(
        tenant=TENANT_A, namespace="ns", resource="r", identifier="i", value=payload, ttl=60
    )

    assert await cache.get(tenant=TENANT_A, namespace="ns", resource="r", identifier="i") == payload


async def test_a_value_that_cannot_be_serialised_is_refused_at_write(cache) -> None:
    """Fail fast, rather than store something no reader can ever parse."""
    from jdlib.caching.errors import CacheSerializationError

    class Unspeakable:
        pass

    with pytest.raises(CacheSerializationError):
        await cache.set(
            tenant=TENANT_A,
            namespace="ns",
            resource="r",
            identifier="i",
            value=Unspeakable(),
            ttl=60,
        )

    assert await cache.get(tenant=TENANT_A, namespace="ns", resource="r", identifier="i") is None


async def test_an_entry_expires(cache) -> None:
    await cache.set(
        tenant=TENANT_A, namespace="ns", resource="r", identifier="e", value={"v": 1}, ttl=1
    )

    assert await cache.get(tenant=TENANT_A, namespace="ns", resource="r", identifier="e") == {
        "v": 1
    }
    await asyncio.sleep(2.0)
    assert await cache.get(tenant=TENANT_A, namespace="ns", resource="r", identifier="e") is None


async def test_the_stored_key_is_the_scoped_key_the_factory_built(cache) -> None:
    """Proves the key shape in the real store, not just in the factory's unit test."""
    raw = await cache.raw_client()
    await cache.set(
        tenant=TENANT_A, namespace="ns", resource="db", identifier="acme", value={"v": 1}, ttl=60
    )

    keys = [k async for k in raw.scan_iter(match="jdlib-test:*")]

    assert keys == [f"jdlib-test:jdlib:v1:{TENANT_A}:ns:db:acme"]


async def test_one_tenant_never_sees_anothers_entry(cache) -> None:
    await cache.set(
        tenant=TENANT_A, namespace="ns", resource="r", identifier="i", value="a", ttl=60
    )

    assert await cache.get(tenant=TENANT_B, namespace="ns", resource="r", identifier="i") is None


async def test_invalidating_a_tenant_leaves_other_tenants_alone(cache) -> None:
    """FLUSHALL was the archived fallback and is every tenant at once."""
    await cache.set(
        tenant=TENANT_A, namespace="ns", resource="r", identifier="i", value="a", ttl=60
    )
    await cache.set(
        tenant=TENANT_B, namespace="ns", resource="r", identifier="i", value="b", ttl=60
    )

    removed = await cache.invalidate_tenant(TENANT_A)

    assert removed == 1
    assert await cache.get(tenant=TENANT_A, namespace="ns", resource="r", identifier="i") is None
    assert await cache.get(tenant=TENANT_B, namespace="ns", resource="r", identifier="i") == "b"


async def test_a_credential_object_never_reaches_redis(cache) -> None:
    from jdlib.caching.errors import CredentialCacheRefusedError
    from jdlib.credentials.refs import SecretRef

    raw = await cache.raw_client()
    before = len([k async for k in raw.scan_iter(match="jdlib-test:*")])

    with pytest.raises(CredentialCacheRefusedError):
        await cache.set(
            tenant=TENANT_A,
            namespace="ns",
            resource="r",
            identifier="i",
            value=SecretRef(handle="db"),
            ttl=60,
        )

    after = len([k async for k in raw.scan_iter(match="jdlib-test:*")])
    assert after == before, "the refusal happened before anything was written"


async def test_offers_no_global_flush(cache) -> None:
    for forbidden in ("flush", "flushall", "flush_all", "clear"):
        assert not hasattr(cache, forbidden), forbidden


async def test_a_ttl_above_the_policy_maximum_is_refused(cache) -> None:
    from jdlib.caching.errors import CachePolicyError
    from jdlib.caching.keys import ScopedKeyFactory
    from jdlib.caching.policy import CachePolicy
    from jdlib.caching.redis import RedisCache

    strict = RedisCache(
        url=cache.url,
        keys=ScopedKeyFactory(),
        prefix="jdlib-test",
        policy=CachePolicy(default_ttl=60, maximum_ttl=120),
    )
    try:
        with pytest.raises(CachePolicyError):
            await strict.set(
                tenant=TENANT_A,
                namespace="ns",
                resource="r",
                identifier="i",
                value={"v": 1},
                ttl=121,
            )
    finally:
        await strict.close()
