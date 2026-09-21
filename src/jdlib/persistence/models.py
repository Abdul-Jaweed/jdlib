from __future__ import annotations

import importlib
import uuid
from typing import Protocol

from jdlib.context import TenantContext
from jdlib.models.base import TenantBase, TenantRouted


def tenant_table_map() -> dict[str, type]:
    for module in ("jdlib.models.org", "jdlib.models.settings", "jdlib.models.audit"):
        importlib.import_module(module)

    found: dict[str, type] = {}

    def walk(cls: type) -> None:
        for subclass in cls.__subclasses__():
            table = getattr(subclass, "__table__", None)
            if (
                table is not None
                and table.metadata is TenantBase.metadata
                and issubclass(subclass, TenantRouted)
            ):
                found[table.name] = subclass
            walk(subclass)

    walk(TenantRouted)
    return found


class WriteFence(Protocol):
    async def assert_writable(self, tenant_id: uuid.UUID) -> None: ...


class NullWriteFence:
    async def assert_writable(self, tenant_id: uuid.UUID) -> None:
        return None


def privileged_bypass(context: TenantContext) -> bool:
    return context.privilege is not None
