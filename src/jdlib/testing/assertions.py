from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, cast

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.context import TenantContext
from jdlib.errors import CrossTenantReferenceError
from jdlib.persistence.session import TenantSession


async def _count(session: TenantSession, model: type[Any]) -> int:
    result = await session.execute(sa.select(sa.func.count()).select_from(model))
    return int(result.scalar_one())


async def assert_scoped_count(
    session_factory: Callable[[], AsyncSession],
    context: TenantContext,
    model: type[Any],
    expected: int,
) -> None:
    """Assert that ``model`` has exactly ``expected`` rows visible to ``context``."""
    async with TenantSession(session_factory(), context) as session:
        count = await _count(session, model)
    assert count == expected, (
        f"expected {expected} {model.__name__} rows for tenant {context.tenant_id}, got {count}"
    )


async def assert_tenant_isolated(
    session_factory: Callable[[], AsyncSession],
    context_a: TenantContext,
    context_b: TenantContext,
    model: type[Any],
    **values: Any,
) -> uuid.UUID:
    """Create a ``model`` row for ``context_b`` and assert ``context_a`` cannot see it.

    Returns the id of the row created for ``context_b``.
    """
    async with TenantSession(session_factory(), context_b) as session:
        row = model(tenant_id=context_b.tenant_id, **values)
        await session.add(row)
        await session.flush()
        row_id = cast(uuid.UUID, row.id)
        await session.commit()
    async with TenantSession(session_factory(), context_a) as session:
        count = await _count(session, model)
        assert count == 0, (
            f"tenant {context_a.tenant_id} sees {count} {model.__name__} rows "
            f"belonging to tenant {context_b.tenant_id}"
        )
        entity = await session.get(model, row_id)
        assert entity is None, (
            f"tenant {context_a.tenant_id} can get {model.__name__} row {row_id} "
            f"belonging to tenant {context_b.tenant_id}"
        )
    return row_id


async def assert_cross_tenant_write_rejected(
    session_factory: Callable[[], AsyncSession],
    context_a: TenantContext,
    model: type[Any],
    **values: Any,
) -> None:
    """Assert a row owned by another tenant cannot be flushed under ``context_a``."""
    other_tenant_id = uuid.uuid4()
    async with TenantSession(session_factory(), context_a) as session:
        await session.add(model(tenant_id=other_tenant_id, **values))
        try:
            await session.flush()
        except CrossTenantReferenceError:
            return
        raise AssertionError(
            f"flush accepted a {model.__name__} row owned by tenant {other_tenant_id} "
            f"under tenant {context_a.tenant_id}"
        )
