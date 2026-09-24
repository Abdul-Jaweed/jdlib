from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from typing import Any

from jdlib.caching.protocol import CacheProvider
from jdlib.credentials.refs import SecretRef
from jdlib.resources.connection import ConnectionConfig
from jdlib.resources.errors import ResourceHydrationError
from jdlib.resources.handle import ResourceHandle
from jdlib.security.audit.emitter import SecurityEventEmitter, emit_safely
from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.context import SecurityContext, current_security_context
from jdlib.security.tracing import TracerLike, security_span

CACHE_NAMESPACE = "resource"

TenantCheck = Callable[[SecurityContext], bool]
ResourceCheck = Callable[[SecurityContext, ResourceHandle], bool]
PrivilegeCheck = Callable[[SecurityContext], bool]


class ResourceResolver:
    """Turns a handle into a connection target, lazily and deterministically.

    It enforces nothing itself. Authorisation is not decided here - there is no third
    enforcement point in this library - so the checks are injected by the caller and a refusal
    fails closed. What this class owns is the mechanism: which tenant the request belongs to
    (taken from the security context, never a parameter), whether a cached target is still
    valid for the current credential version, and that a cached value is a connection
    configuration before it is handed out.
    """

    def __init__(
        self,
        *,
        secrets: Any,
        cache: CacheProvider,
        check_tenant: TenantCheck | None = None,
        check_resource: ResourceCheck | None = None,
        check_privilege: PrivilegeCheck | None = None,
        tracer: TracerLike | None = None,
        emitter: SecurityEventEmitter | None = None,
    ) -> None:
        self._secrets = secrets
        self._cache = cache
        self._check_tenant = check_tenant
        self._check_resource = check_resource
        self._check_privilege = check_privilege
        self._tracer = tracer
        self._emitter = emitter
        self._locks: dict[str, asyncio.Lock] = {}

    async def hydrate(self, handle: ResourceHandle) -> ConnectionConfig:
        """The boundary. One span per hydration, at the entry point only.

        The checks, the cache lookups and the credential resolution inside are helpers; a span
        per helper would be the per-method instrumentation this programme rejected, so the
        operation is named once and the outcome is recorded on that one span.
        """
        with security_span(
            self._tracer,
            "resources.hydrate",
            attributes={"security.operation": "resources.hydrate"},
        ) as span:
            try:
                config = await self._hydrate_inner(handle)
            except Exception as exc:
                span.set_attribute("security.result", "refused")
                emit_safely(
                    self._emitter,
                    SecurityAuditEvent(
                        event_type=SecurityEventType.RESOURCE_HYDRATION_REFUSED,
                        outcome=AuditOutcome.DENIED,
                        action="resource.hydrate",
                        source=AuditSource.SERVICE,
                        resource_type="resource",
                        resource_id=handle.value,
                        metadata={"error": type(exc).__name__},
                    ),
                )
                raise
            span.set_attribute("security.result", "hydrated")
            emit_safely(
                self._emitter,
                SecurityAuditEvent(
                    event_type=SecurityEventType.RESOURCE_HYDRATED,
                    outcome=AuditOutcome.SUCCESS,
                    action="resource.hydrate",
                    source=AuditSource.SERVICE,
                    resource_type="resource",
                    resource_id=handle.value,
                ),
            )
            return config

    async def _hydrate_inner(self, handle: ResourceHandle) -> ConnectionConfig:
        try:
            context = current_security_context()
        except Exception as exc:  # no context bound at all
            raise ResourceHydrationError(
                f"cannot hydrate {handle.value}: no security context is bound, so the tenant "
                "the resource belongs to is unknown"
            ) from exc

        try:
            tenant = context.require_tenant()
        except Exception as exc:
            raise ResourceHydrationError(
                f"cannot hydrate {handle.value}: the security context carries no tenant"
            ) from exc

        if self._check_tenant is not None and not self._check_tenant(context):
            raise ResourceHydrationError(
                f"cannot hydrate {handle.value}: the tenant is not permitted"
            )
        if self._check_resource is not None and not self._check_resource(context, handle):
            raise ResourceHydrationError(
                f"cannot hydrate {handle.value}: the resource is not authorized for this tenant"
            )
        if self._check_privilege is not None and not self._check_privilege(context):
            raise ResourceHydrationError(
                f"cannot hydrate {handle.value}: the privilege has expired"
            )

        version = self._version(handle)
        if version is None:
            raise ResourceHydrationError(
                f"cannot hydrate {handle.value}: no credential is registered for this handle. "
                "There is no fallback to a shared target"
            )

        scoped = f"{tenant.tenant_id}:{handle.value}:{version}"
        cached = self._cache.get(
            tenant=str(tenant.tenant_id),
            namespace=CACHE_NAMESPACE,
            resource=handle.value,
            identifier=version,
        )
        if cached is not None:
            if not isinstance(cached, ConnectionConfig):
                raise ResourceHydrationError(
                    f"cannot hydrate {handle.value}: the cache holds a "
                    f"{type(cached).__name__} under this key, not a connection configuration"
                )
            return cached

        lock = self._locks.setdefault(scoped, asyncio.Lock())
        async with lock:
            cached = self._cache.get(
                tenant=str(tenant.tenant_id),
                namespace=CACHE_NAMESPACE,
                resource=handle.value,
                identifier=version,
            )
            if isinstance(cached, ConnectionConfig):
                return cached

            resolved = await self._resolve(handle)
            config = ConnectionConfig(
                handle=handle.value,
                target=resolved,
                credential_version=version,
                tenant_id=str(tenant.tenant_id),
            )
            self._cache.set(
                tenant=str(tenant.tenant_id),
                namespace=CACHE_NAMESPACE,
                resource=handle.value,
                identifier=version,
                value=config,
                ttl=300,
            )
            return config

    def _version(self, handle: ResourceHandle) -> str | None:
        """The current credential version, or None when the handle has no credential.

        Read from the provider rather than remembered here, which is what makes rotation
        work: a rotated credential yields a different version, hence a different cache key,
        hence a rebuild rather than a stale target.
        """
        current = getattr(self._secrets, "current_version", None)
        if current is None:
            return None
        version = current(handle.value)
        if version is None:
            return None
        return str(getattr(version, "value", version))

    async def _resolve(self, handle: ResourceHandle) -> str:
        resolved = self._secrets.resolve(SecretRef(handle=handle.value))
        if inspect.isawaitable(resolved):
            resolved = await resolved
        value = getattr(resolved, "value", resolved)
        if not isinstance(value, str) or not value:
            raise ResourceHydrationError(
                f"cannot hydrate {handle.value}: the credential provider returned no value"
            )
        return value
