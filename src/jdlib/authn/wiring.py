from __future__ import annotations

import uuid

from jdlib.authz.reader import AccessReader
from jdlib.context import Principal, TenantRecord, TenantRef
from jdlib.control.registry import TenantRegistry


class PrincipalDirectoryAdapter:
    def __init__(self, reader: AccessReader) -> None:
        self._reader = reader

    async def is_active(self, principal: Principal) -> bool:
        return await self._reader.principal_active(principal)


class TenantDirectoryAdapter:
    def __init__(self, registry: TenantRegistry) -> None:
        self._registry = registry

    async def get(self, ref: TenantRef) -> TenantRecord | None:
        return await self._registry.find(ref)


class EntitlementAdapter:
    def __init__(self, reader: AccessReader) -> None:
        self._reader = reader

    async def can_act(self, principal: Principal, tenant_id: uuid.UUID) -> bool:
        if not await self._reader.principal_active(principal):
            return False
        return await self._reader.membership_active(principal, tenant_id)
