from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import text

from jdlib.data.capabilities import ConnectorCapabilities
from jdlib.data.connector import AuthorizationRefusedError
from jdlib.data.errors import ConnectorError, ConnectorTimeoutError
from jdlib.data.policy import ConnectionPolicy
from jdlib.resources.connection import ConnectionConfig
from jdlib.security.context import SecurityContext

READ_PREFIXES = ("select", "with", "table", "values")
_COMMENT = re.compile(r"(--[^\n]*|/\*.*?\*/)", re.S)


class PostgresConnector:
    """A read-only PostgreSQL connector over the library's own async engine layer.

    It reuses ``create_async_engine`` and the pool rule already used elsewhere in this
    library (``pool_pre_ping``) rather than adding an engine abstraction, and it builds its
    engine per open from the resolved target - never from a DSN it holds, because a stored
    DSN is a credential that outlives its rotation.

    The declared capability is enforced, not decorative: this connector says
    ``writes=False`` and refuses a statement that is not a read. The check is deliberately
    shallow - first keyword, comments stripped - because the thorough analyser already
    exists elsewhere in the library for the tenant plane; a second, competing SQL analyser
    is exactly the duplication the naming decisions forbid.
    """

    capabilities = ConnectorCapabilities(
        name="postgres", reads=True, writes=False, transactions=False, dialect="postgresql"
    )

    def __init__(self, *, policy: ConnectionPolicy | None = None) -> None:
        self._policy = policy or ConnectionPolicy()
        self._engine: Any = None

    async def open(self, *, target: ConnectionConfig, context: SecurityContext) -> None:
        tenant = context.require_tenant()
        if str(tenant.tenant_id) != target.tenant_id:
            raise AuthorizationRefusedError(
                f"connector postgres: the authorized context is for tenant {tenant.tenant_id}, "
                f"but the target belongs to {target.tenant_id}"
            )
        from sqlalchemy.ext.asyncio import create_async_engine

        # A target may carry connection settings of its own - a search_path, most often. The
        # DSN cannot express them: SQLAlchemy passes unknown URL parameters to the driver and
        # asyncpg rejects them, which is why the schema travels here instead.
        connect_args: dict[str, Any] = {}
        if target.server_settings:
            connect_args["server_settings"] = dict(target.server_settings)
        self._engine = create_async_engine(
            target.target, pool_pre_ping=True, connect_args=connect_args
        )

    @asynccontextmanager
    async def opened(
        self, *, target: ConnectionConfig, context: SecurityContext
    ) -> AsyncIterator[PostgresConnector]:
        await self.open(target=target, context=context)
        try:
            yield self
        finally:
            await self.close()

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None

    async def health(self) -> bool:
        if self._engine is None:
            return False
        try:
            async with self._engine.connect() as connection:
                await connection.execute(text("select 1"))
        except Exception:
            return False
        return True

    async def execute(
        self, *, statement: str, params: tuple[Any, ...] = ()
    ) -> list[dict[str, Any]]:
        if self._engine is None:
            raise ConnectorError("connector postgres: execute before open")
        self._refuse_non_read(statement)
        try:
            return await asyncio.wait_for(
                self._run(statement, params), timeout=self._policy.statement_timeout
            )
        except TimeoutError as exc:
            raise ConnectorTimeoutError(
                f"connector postgres: statement exceeded the "
                f"{self._policy.statement_timeout}s policy timeout"
            ) from exc

    async def _run(self, statement: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        async with self._engine.connect() as connection:
            result = await connection.execute(text(statement), dict(params) if params else {})
            return [dict(row._mapping) for row in result]

    @staticmethod
    def _refuse_non_read(statement: str) -> None:
        stripped = _COMMENT.sub(" ", statement).strip().lower()
        first = stripped.split(None, 1)[0] if stripped else ""
        if first not in READ_PREFIXES:
            raise ConnectorError(
                "connector postgres declares writes=False and refuses a statement that is not "
                f"a read: {first or '<empty>'!r}"
            )
