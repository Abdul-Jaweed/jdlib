from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import TypeVar

from jdlib.context import (
    EntitlementChecker,
    EnvelopeCodec,
    Principal,
    PrincipalDirectory,
    ServabilityChecker,
    TenantContext,
    TenantDirectory,
    TenantRef,
    context_scope,
)
from jdlib.errors import TenantAccessDenied, TenantNotFound, UnknownPrincipal

F = TypeVar("F", bound=Callable[..., Awaitable[object]])


class ContextPropagator:
    def __init__(
        self,
        *,
        codec: EnvelopeCodec,
        principals: PrincipalDirectory,
        tenants: TenantDirectory,
        servability: ServabilityChecker,
        entitlements: EntitlementChecker,
    ) -> None:
        self._codec = codec
        self._principals = principals
        self._tenants = tenants
        self._servability = servability
        self._entitlements = entitlements

    async def reconstruct(self, token: str) -> TenantContext:
        envelope = self._codec.decode(token)
        principal = Principal(kind=envelope.principal_type, id=envelope.principal_id)
        if not await self._principals.is_active(principal):
            raise UnknownPrincipal(str(principal.id))
        record = await self._tenants.get(TenantRef(id=envelope.tenant_id))
        if record is None:
            raise TenantNotFound(str(envelope.tenant_id))
        if not await self._entitlements.can_act(principal, record.id):
            raise TenantAccessDenied(f"principal {principal.id} cannot act in {record.id}")
        await self._servability.assert_servable(record.id)
        return TenantContext(
            tenant_id=record.id,
            tenant_slug=record.slug,
            strategy=record.strategy,
            principal=principal,
            request_id=envelope.request_id,
            correlation_id=envelope.correlation_id,
            trace_id=envelope.trace_id,
            privilege=None,
        )


def tenant_job(propagator: ContextPropagator) -> Callable[[F], F]:
    def decorate(fn: F) -> F:
        @functools.wraps(fn)
        async def wrapper(envelope: str, *args: object, **kwargs: object) -> object:
            context = await propagator.reconstruct(envelope)
            with context_scope(context):
                return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate
