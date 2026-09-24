from __future__ import annotations

import inspect
from collections.abc import AsyncIterator
from typing import Any, Protocol, runtime_checkable

from jdlib.resources.connection import ConnectionConfig
from jdlib.security.context import SecurityContext
from jdlib.storage.metadata import ObjectMetadata, StoredObject

REQUIRED_METHODS = (
    "open",
    "close",
    "health",
    "put",
    "get",
    "metadata",
    "stream",
    "list",
    "delete",
)


@runtime_checkable
class ObjectStorageProvider(Protocol):
    """What a storage backend must implement. Asynchronous throughout (ADR-14).

    ``open`` receives the resolved target and the security context that authorized it, and an
    implementation must verify the second covers the first before it talks to anything.
    """

    async def open(self, *, target: ConnectionConfig, context: SecurityContext) -> None: ...

    async def close(self) -> None: ...

    async def health(self) -> bool: ...

    async def put(
        self, key: str, data: bytes, *, content_type: str | None = None
    ) -> StoredObject: ...

    async def get(self, key: str) -> bytes: ...

    async def metadata(self, key: str) -> ObjectMetadata: ...

    def stream(self, key: str) -> AsyncIterator[bytes]: ...

    async def list(self, *, prefix: str = "") -> list[StoredObject]: ...

    async def delete(self, key: str) -> None: ...


def assert_object_storage_contract(candidate: Any) -> list[str]:
    """Every problem with a candidate backend, so one can be refused at startup.

    A backend is not exported until this returns nothing: a provider class in the public
    surface is a claim that it works, and the claim should be checked rather than intended.
    """
    problems: list[str] = []
    for name in REQUIRED_METHODS:
        method = getattr(candidate, name, None)
        if method is None:
            problems.append(f"{name} is missing")
            continue
        if name == "stream":
            if not inspect.isasyncgenfunction(method) and not inspect.iscoroutinefunction(method):
                problems.append("stream must be an async generator or coroutine")
            continue
        if not inspect.iscoroutinefunction(method):
            problems.append(f"{name} must be async, and is not")
    return problems
