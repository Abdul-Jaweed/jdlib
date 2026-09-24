"""Scoped caching (successor Phase 3). RED first, per the programme's TDD rule.

Three properties, in priority order:

1. **ADR-2, the reason this phase exists**: a credential must not be storable in a shared
   cache. The archived system's worst defect was serialising fully decrypted tenant
   documents - passwords and a private key - into Redis for twelve hours. That is not
   prevented here by documentation; the write is refused, and the guard is tested.
2. **Tenant scope by construction**: a key cannot be built without a tenant where the
   namespace requires one, and one tenant's entries are never visible to another.
3. **Serialisation round-trips**: the archived cache wrote Python repr() values that could
   never be parsed back, so those entries missed forever. A value must come out as it went in.

Time is injected (the existing idiom from the reliability inventory), so TTL tests do not
sleep and cannot flake.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"
SENTINEL = "plain-text-that-must-never-be-cached"


class _Clock:
    """Injected time source: TTL behaviour without sleeping."""

    def __init__(self) -> None:
        self.now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class _SecretValue:
    """Stands in for a resolved secret: the type is what the guard keys on."""

    def __init__(self, value: str) -> None:
        self.value = value


class TestScopedKeyFactory:
    def test_builds_a_versioned_key_in_the_documented_shape(self) -> None:
        from jdlib.caching.keys import ScopedKeyFactory

        keys = ScopedKeyFactory()
        key = keys.build(tenant=TENANT_A, namespace="resourcedef", resource="db", identifier="acme")

        assert key == f"jdlib:v1:{TENANT_A}:resourcedef:db:acme"

    def test_refuses_a_tenant_scoped_key_with_no_tenant(self) -> None:
        """The whole point: scope cannot be omitted by accident."""
        from jdlib.caching.errors import CacheKeyError
        from jdlib.caching.keys import ScopedKeyFactory

        keys = ScopedKeyFactory()

        with pytest.raises(CacheKeyError):
            keys.build(tenant="", namespace="resourcedef", resource="db", identifier="acme")

    def test_refuses_empty_components_rather_than_building_an_ambiguous_key(self) -> None:
        from jdlib.caching.errors import CacheKeyError
        from jdlib.caching.keys import ScopedKeyFactory

        keys = ScopedKeyFactory()

        for bad in ({"namespace": ""}, {"resource": ""}, {"identifier": ""}):
            with pytest.raises(CacheKeyError):
                keys.build(
                    tenant=TENANT_A,
                    namespace=bad.get("namespace", "ns"),
                    resource=bad.get("resource", "res"),
                    identifier=bad.get("identifier", "id"),
                )

    def test_a_component_containing_the_separator_cannot_collide_with_another_key(self) -> None:
        """Delimiter safety: the archived key used bare concatenation with no separators."""
        from jdlib.caching.errors import CacheKeyError
        from jdlib.caching.keys import ScopedKeyFactory

        keys = ScopedKeyFactory()

        with pytest.raises(CacheKeyError):
            keys.build(tenant=TENANT_A, namespace="ns", resource="a:b", identifier="c")

    def test_global_keys_are_allowed_for_shared_namespaces(self) -> None:
        from jdlib.caching.keys import ScopedKeyFactory

        keys = ScopedKeyFactory()

        assert keys.build_global(namespace="permissions", identifier="catalog") == (
            "jdlib:v1:_global:permissions:catalog"
        )

    def test_tenant_prefix_covers_every_key_of_that_tenant(self) -> None:
        """Invalidation needs a prefix that cannot match another tenant."""
        from jdlib.caching.keys import ScopedKeyFactory

        keys = ScopedKeyFactory()
        prefix = keys.tenant_prefix(TENANT_A)

        assert keys.build(tenant=TENANT_A, namespace="ns", resource="r", identifier="i").startswith(
            prefix
        )
        assert not keys.build(
            tenant=TENANT_B, namespace="ns", resource="r", identifier="i"
        ).startswith(prefix)


class TestLocalCache:
    def _cache(self, clock, **kwargs):
        from jdlib.caching.keys import ScopedKeyFactory
        from jdlib.caching.local import LocalCache

        return LocalCache(keys=ScopedKeyFactory(), clock=clock, **kwargs)

    def test_a_value_comes_back_as_it_went_in(
        self,
    ) -> None:
        """The archived cache wrote repr() and could never read it back."""
        clock = _Clock()
        cache = self._cache(clock)
        payload = {"rows": [{"NAME": "x"}], "count": 2}

        cache.set(
            tenant=TENANT_A, namespace="ns", resource="r", identifier="i", value=payload, ttl=60
        )

        assert cache.get(tenant=TENANT_A, namespace="ns", resource="r", identifier="i") == payload

    def test_an_expired_entry_is_a_miss(self) -> None:
        clock = _Clock()
        cache = self._cache(clock)
        cache.set(tenant=TENANT_A, namespace="ns", resource="r", identifier="i", value="v", ttl=30)

        clock.advance(31)

        assert cache.get(tenant=TENANT_A, namespace="ns", resource="r", identifier="i") is None

    def test_one_tenant_never_sees_anothers_entry(self) -> None:
        clock = _Clock()
        cache = self._cache(clock)
        cache.set(
            tenant=TENANT_A, namespace="ns", resource="r", identifier="i", value="a-value", ttl=60
        )

        assert cache.get(tenant=TENANT_B, namespace="ns", resource="r", identifier="i") is None

    def test_invalidating_a_namespace_leaves_other_namespaces_alone(self) -> None:
        clock = _Clock()
        cache = self._cache(clock)
        cache.set(
            tenant=TENANT_A, namespace="ns-one", resource="r", identifier="i", value=1, ttl=60
        )
        cache.set(
            tenant=TENANT_A, namespace="ns-two", resource="r", identifier="i", value=2, ttl=60
        )

        removed = cache.invalidate_namespace(tenant=TENANT_A, namespace="ns-one")

        assert removed == 1
        assert cache.get(tenant=TENANT_A, namespace="ns-one", resource="r", identifier="i") is None
        assert cache.get(tenant=TENANT_A, namespace="ns-two", resource="r", identifier="i") == 2

    def test_invalidating_a_tenant_leaves_other_tenants_alone(self) -> None:
        clock = _Clock()
        cache = self._cache(clock)
        cache.set(tenant=TENANT_A, namespace="ns", resource="r", identifier="i", value="a", ttl=60)
        cache.set(tenant=TENANT_B, namespace="ns", resource="r", identifier="i", value="b", ttl=60)

        removed = cache.invalidate_tenant(TENANT_A)

        assert removed == 1
        assert cache.get(tenant=TENANT_A, namespace="ns", resource="r", identifier="i") is None
        assert cache.get(tenant=TENANT_B, namespace="ns", resource="r", identifier="i") == "b"

    def test_offers_no_global_flush(self) -> None:
        """The archived invalidation fallback was FLUSHALL, which is every tenant at once."""
        clock = _Clock()
        cache = self._cache(clock)

        for forbidden in ("flush", "flushall", "clear", "clear_all"):
            assert not hasattr(cache, forbidden), forbidden

    def test_a_ttl_above_the_namespace_maximum_is_refused(self) -> None:
        from jdlib.caching.errors import CachePolicyError
        from jdlib.caching.policy import CachePolicy

        clock = _Clock()
        policy = CachePolicy(default_ttl=60, maximum_ttl=300)
        cache = self._cache(clock, policy=policy)

        with pytest.raises(CachePolicyError):
            cache.set(
                tenant=TENANT_A, namespace="ns", resource="r", identifier="i", value="v", ttl=301
            )


class TestCredentialRefusal:
    """ADR-2. These are the tests the phase is for."""

    def _cache(self):
        from jdlib.caching.keys import ScopedKeyFactory
        from jdlib.caching.local import LocalCache

        return LocalCache(keys=ScopedKeyFactory(), clock=_Clock())

    def test_a_resolved_secret_cannot_be_stored(self) -> None:
        from jdlib.caching.errors import CredentialCacheRefusedError
        from jdlib.credentials.refs import ResolvedSecret, SecretRef, SecretVersion

        cache = self._cache()
        resolved = ResolvedSecret(
            ref=SecretRef(handle="db"), version=SecretVersion("1"), value=SENTINEL
        )

        with pytest.raises(CredentialCacheRefusedError):
            cache.set(
                tenant=TENANT_A,
                namespace="ns",
                resource="r",
                identifier="i",
                value=resolved,
                ttl=60,
            )

    def test_a_bare_secret_reference_cannot_be_stored_either(self) -> None:
        from jdlib.caching.errors import CredentialCacheRefusedError
        from jdlib.credentials.refs import SecretRef

        cache = self._cache()

        with pytest.raises(CredentialCacheRefusedError):
            cache.set(
                tenant=TENANT_A,
                namespace="ns",
                resource="r",
                identifier="i",
                value=SecretRef(handle="db"),
                ttl=60,
            )

    def test_a_credential_inside_a_container_is_also_refused(self) -> None:
        """Wrapping it in a dict must not be a way around the guard."""
        from jdlib.caching.errors import CredentialCacheRefusedError
        from jdlib.credentials.refs import SecretRef

        cache = self._cache()

        for wrapper in (
            {"secret": SecretRef(handle="db")},
            [SecretRef(handle="db")],
            (SecretRef(handle="db"),),
        ):
            with pytest.raises(CredentialCacheRefusedError):
                cache.set(
                    tenant=TENANT_A,
                    namespace="ns",
                    resource="r",
                    identifier="i",
                    value=wrapper,
                    ttl=60,
                )

    def test_the_refusal_error_is_a_jdlib_error(self) -> None:
        from jdlib.caching.errors import CredentialCacheRefusedError
        from jdlib.errors import JdlibError

        assert issubclass(CredentialCacheRefusedError, JdlibError)

    def test_the_refusal_names_the_namespace_not_the_value(self) -> None:
        from jdlib.caching.errors import CredentialCacheRefusedError
        from jdlib.credentials.refs import SecretRef

        cache = self._cache()

        with pytest.raises(CredentialCacheRefusedError) as caught:
            cache.set(
                tenant=TENANT_A,
                namespace="resourcedef",
                resource="r",
                identifier="i",
                value=SecretRef(handle="db"),
                ttl=60,
            )

        assert "resourcedef" in str(caught.value)
        assert SENTINEL not in str(caught.value)

    def test_ordinary_values_are_unaffected(self) -> None:
        """The guard must not be so broad that it refuses normal cached data."""
        cache = self._cache()

        cache.set(
            tenant=TENANT_A,
            namespace="ns",
            resource="r",
            identifier="i",
            value={"rows": [1, 2]},
            ttl=60,
        )

        assert cache.get(tenant=TENANT_A, namespace="ns", resource="r", identifier="i") == {
            "rows": [1, 2]
        }
