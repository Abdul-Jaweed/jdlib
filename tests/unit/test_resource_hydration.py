"""Resource hydration (successor Phase 4). RED first.

The gate is the directive's own list, one named test per item: right tenant, wrong tenant,
missing context, suspended tenant, unauthorized resource, revoked credential, expired
privilege, cache isolation, cache poisoning, credential leakage, concurrency.

Four decisions these tests pin down:

* The tenant comes from the SECURITY CONTEXT and never from a parameter, so a caller cannot
  hydrate another tenant's resource by asking politely.
* Hydration is lazy and aware of the credential version: a rotated credential rebuilds the
  target rather than serving a stale one.
* The resolver enforces nothing itself - there is no third enforcement point. The checks are
  injected by the caller, and a refusal fails closed rather than falling back to anything.
* A cached entry is validated before it is served, so a poisoned cache cannot become a
  connection target.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

import pytest

from jdlib.caching.keys import ScopedKeyFactory
from jdlib.caching.local import LocalCache
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.credentials.rotation import VersionedSecretProvider
from jdlib.persistence.secrets import MemorySecretProvider
from jdlib.resources.errors import ResourceHydrationError
from jdlib.resources.handle import ResourceHandle
from jdlib.resources.resolver import ResourceResolver
from jdlib.security.context import AuthMethod, SecurityContext, security_context_scope

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
HANDLE = "db-tenant-acme"
TARGET = "postgres://host:5432/acme"


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def _context(tenant_id: uuid.UUID = TENANT_ID) -> SecurityContext:
    principal = Principal(kind=PrincipalKind.USER, id=uuid.uuid4())
    tenant = TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req-1",
        correlation_id="corr-1",
        trace_id="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    )
    return SecurityContext.from_tenant_context(tenant=tenant, auth_method=AuthMethod.SERVICE)


class _CountingSecrets:
    """Counts resolutions, so 'resolved once' and 'resolved per tenant' are asserted."""

    def __init__(self, inner) -> None:
        self.inner = inner
        self.resolutions = 0

    def resolve(self, ref):
        self.resolutions += 1
        return self.inner.resolve(ref)

    def current_version(self, handle):
        return self.inner.current_version(handle)


def _secrets(**values) -> VersionedSecretProvider:
    return VersionedSecretProvider(MemorySecretProvider(values))


def _cache() -> LocalCache:
    return LocalCache(keys=ScopedKeyFactory(), clock=_Clock())


def _resolver(secrets, **kwargs) -> ResourceResolver:
    return ResourceResolver(secrets=secrets, cache=_cache(), **kwargs)


# --- the gate's eleven, in order -----------------------------------------------------------


async def test_a_resource_is_hydrated_for_the_right_tenant() -> None:
    resolver = _resolver(_secrets(**{HANDLE: TARGET}))

    with security_context_scope(_context()):
        target = await resolver.hydrate(ResourceHandle(HANDLE))

    assert target.target == TARGET
    assert target.handle == HANDLE


async def test_a_wrong_tenant_neither_inherits_nor_is_harmed_by_anothers_entry() -> None:
    """Isolation is this class's job; *authorisation* for the handle is the injected check's.

    So the assertion is the property the resolver owns: one tenant's entry cannot satisfy
    another (B re-resolves), and corrupting A's entry cannot make B fail.
    """
    secrets = _CountingSecrets(_secrets(**{HANDLE: TARGET}))
    cache = _cache()
    resolver = ResourceResolver(secrets=secrets, cache=cache)

    with security_context_scope(_context(TENANT_ID)):
        first = await resolver.hydrate(ResourceHandle(HANDLE))
        version = secrets.current_version(HANDLE)
        cache.set(
            tenant=str(TENANT_ID),
            namespace="resource",
            resource=HANDLE,
            identifier=version.value,
            value={"poisoned": True},
            ttl=60,
        )

    with security_context_scope(_context(OTHER_TENANT_ID)):
        second = await resolver.hydrate(ResourceHandle(HANDLE))

    assert second.target == TARGET
    assert second is not first
    assert secrets.resolutions == 2


async def test_missing_security_context_fails_closed() -> None:
    resolver = _resolver(_secrets(**{HANDLE: TARGET}))

    with pytest.raises(ResourceHydrationError):
        await resolver.hydrate(ResourceHandle(HANDLE))


async def test_a_suspended_tenant_is_refused() -> None:
    resolver = _resolver(_secrets(**{HANDLE: TARGET}), check_tenant=lambda context: False)

    with security_context_scope(_context()), pytest.raises(ResourceHydrationError):
        await resolver.hydrate(ResourceHandle(HANDLE))


async def test_an_unauthorized_resource_is_refused() -> None:
    resolver = _resolver(_secrets(**{HANDLE: TARGET}), check_resource=lambda context, handle: False)

    with security_context_scope(_context()), pytest.raises(ResourceHydrationError):
        await resolver.hydrate(ResourceHandle(HANDLE))


async def test_a_rotated_credential_rebuilds_instead_of_serving_a_stale_target() -> None:
    """The cached target carries its credential version; a rotation must not be served."""
    secrets = _secrets(**{HANDLE: "postgres://host:5432/v1"})
    resolver = _resolver(secrets)

    with security_context_scope(_context()):
        first = await resolver.hydrate(ResourceHandle(HANDLE))
        secrets.rotate(HANDLE, new_value="postgres://host:5432/v2", version="2")
        second = await resolver.hydrate(ResourceHandle(HANDLE))

    assert first.target == "postgres://host:5432/v1"
    assert second.target == "postgres://host:5432/v2"


async def test_an_expired_privilege_is_refused() -> None:
    resolver = _resolver(_secrets(**{HANDLE: TARGET}), check_privilege=lambda context: False)

    with security_context_scope(_context()), pytest.raises(ResourceHydrationError):
        await resolver.hydrate(ResourceHandle(HANDLE))


async def test_two_tenants_never_share_a_cache_entry() -> None:
    secrets = _CountingSecrets(_secrets(**{HANDLE: TARGET}))
    resolver = _resolver(secrets)

    with security_context_scope(_context(TENANT_ID)):
        await resolver.hydrate(ResourceHandle(HANDLE))
    with security_context_scope(_context(OTHER_TENANT_ID)):
        await resolver.hydrate(ResourceHandle(HANDLE))

    assert secrets.resolutions == 2, "each tenant resolved its own target"


async def test_a_poisoned_cache_entry_is_refused_rather_than_served() -> None:
    secrets = _secrets(**{HANDLE: TARGET})
    cache = _cache()
    resolver = ResourceResolver(secrets=secrets, cache=cache)

    with security_context_scope(_context()):
        await resolver.hydrate(ResourceHandle(HANDLE))
        version = secrets.current_version(HANDLE)
        cache.set(
            tenant=str(TENANT_ID),
            namespace="resource",
            resource=HANDLE,
            identifier=version.value,
            value={"not": "a target"},
            ttl=60,
        )

        with pytest.raises(ResourceHydrationError):
            await resolver.hydrate(ResourceHandle(HANDLE))


async def test_no_credential_value_is_renderable_from_a_hydrated_resource() -> None:
    """The target string is credential material, so nothing may render it."""
    resolver = _resolver(_secrets(**{HANDLE: "postgres://user:secret-password@host/acme"}))

    with security_context_scope(_context()):
        target = await resolver.hydrate(ResourceHandle(HANDLE))
        rendered = repr(target)

    assert "secret-password" not in rendered
    assert "secret-password" not in str(target)
    assert "secret-password" not in repr(ResourceHandle(HANDLE))


async def test_concurrent_hydration_of_one_handle_resolves_once() -> None:
    secrets = _CountingSecrets(_secrets(**{HANDLE: TARGET}))
    resolver = _resolver(secrets)

    with security_context_scope(_context()):
        results = await asyncio.gather(
            *[resolver.hydrate(ResourceHandle(HANDLE)) for _ in range(8)]
        )

    assert secrets.resolutions == 1
    assert len({r.target for r in results}) == 1
