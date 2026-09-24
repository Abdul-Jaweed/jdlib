from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from jdlib.data.capabilities import ConnectorCapabilities
from jdlib.data.errors import AuthorizationRefusedError
from jdlib.resources.connection import ConnectionConfig
from jdlib.security.context import SecurityContext

__all__ = ["AuthorizationRefusedError", "DataConnector"]


@runtime_checkable
class DataConnector(Protocol):
    """What an engine adapter must implement. Asynchronous throughout (ADR-14).

    ``open`` receives both the resolved target and the security context that authorized it,
    and an implementation must verify the second covers the first before it opens anything.
    That check is the connector's own - this library has no third enforcement point, and the
    connector is the only party that can see both halves at once.
    """

    @property
    def capabilities(self) -> ConnectorCapabilities: ...

    async def open(self, *, target: ConnectionConfig, context: SecurityContext) -> None: ...

    async def close(self) -> None: ...

    async def health(self) -> bool: ...

    async def execute(
        self, *, statement: str, params: tuple[Any, ...] = ()
    ) -> list[dict[str, Any]]: ...
