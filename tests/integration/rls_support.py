from __future__ import annotations

import asyncio
from collections.abc import Callable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from jdlib.persistence.strategies.rls import retryable_ddl_error

LOCK_TIMEOUT = "5s"
ATTEMPTS = 3
RETRY_DELAY = 0.25

_TERMINATE_IDLE = sa.text(
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
    "WHERE datname = current_database() "
    "AND pid <> pg_backend_pid() "
    "AND state = 'idle in transaction'"
)


async def run_rls_ddl(engine: AsyncEngine, callback: Callable[[sa.Connection], object]) -> None:
    """Run RLS DDL with a bounded lock timeout and retry.

    Pooled connections from earlier statements can linger ``idle in
    transaction`` holding locks on the tenant tables. Terminate those (the
    database is test-owned), cap the lock wait, and retry a transient
    deadlock/lock-timeout instead of flaking the suite.
    """
    for attempt in range(ATTEMPTS):
        try:
            async with engine.begin() as connection:
                await connection.execute(
                    sa.text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
                )
                await connection.execute(_TERMINATE_IDLE)
                await connection.run_sync(callback)
            return
        except Exception as exc:
            if attempt + 1 >= ATTEMPTS or not retryable_ddl_error(exc):
                raise
            await asyncio.sleep(RETRY_DELAY * (attempt + 1))
