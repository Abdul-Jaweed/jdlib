from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, cast

import sqlalchemy as sa

from jdlib.persistence.session import TenantSession


class TenantRepository[ModelT]:
    def __init__(self, session: TenantSession, model: type[ModelT]) -> None:
        self._session = session
        self._model = model

    def _live_criteria(self) -> list[sa.ColumnElement[bool]]:
        model = cast(Any, self._model)
        if hasattr(model, "deleted_at"):
            return [model.deleted_at.is_(None)]
        return []

    async def get(self, entity_id: uuid.UUID) -> ModelT | None:
        model = cast(Any, self._model)
        if not hasattr(model, "deleted_at"):
            return await self._session.get(self._model, entity_id)
        statement = sa.select(self._model).where(
            model.id == entity_id, *self._live_criteria()
        )
        result = await self._session.execute(statement)
        return result.scalars().first()

    async def list(
        self,
        *criteria: sa.ColumnElement[bool],
        order_by: sa.ColumnElement[Any] | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> Sequence[ModelT]:
        statement = sa.select(self._model).where(*self._live_criteria())
        if criteria:
            statement = statement.where(*criteria)
        if order_by is not None:
            statement = statement.order_by(order_by)
        if limit is not None:
            statement = statement.limit(limit)
        if offset is not None:
            statement = statement.offset(offset)
        result = await self._session.execute(statement)
        return result.scalars().all()

    async def add(self, obj: ModelT) -> ModelT:
        await self._session.add(obj)
        await self._session.flush()
        return obj

    async def update(self, obj: ModelT, **changes: Any) -> ModelT:
        for field, value in changes.items():
            setattr(obj, field, value)
        await self._session.flush()
        return obj

    async def soft_delete(self, obj: ModelT) -> None:
        if not hasattr(obj, "deleted_at"):
            raise TypeError(f"{type(obj).__name__} is not soft-deletable")
        cast(Any, obj).deleted_at = datetime.now(UTC)
        await self._session.flush()

    async def count(self, *criteria: sa.ColumnElement[bool]) -> int:
        statement = sa.select(sa.func.count()).select_from(self._model).where(
            *self._live_criteria()
        )
        if criteria:
            statement = statement.where(*criteria)
        result = await self._session.execute(statement)
        return int(result.scalar_one())
