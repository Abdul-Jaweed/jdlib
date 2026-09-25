from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession


class ControlPlaneSession:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def __aenter__(self) -> ControlPlaneSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._session.close()

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()

    async def flush(self) -> None:
        await self._session.flush()

    async def execute(
        self, statement: sa.Executable, parameters: Mapping[str, Any] | None = None
    ) -> sa.Result[Any]:
        # Parameters are optional so every existing call keeps its shape; the audit sink is
        # the caller that needs them (`set_config` for the transaction's `application_name`).
        return await self._session.execute(statement, parameters or {})

    async def get(self, model: type[Any], entity_id: Any) -> Any | None:
        return await self._session.get(model, entity_id)

    def add(self, obj: Any) -> None:
        self._session.add(obj)

    async def delete(self, obj: Any) -> None:
        await self._session.delete(obj)
