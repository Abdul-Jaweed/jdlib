from __future__ import annotations

import asyncio
from collections.abc import Callable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.rls import (
    _DDL_ATTEMPTS,
    _DDL_LOCK_TIMEOUT,
    _DDL_RETRY_DELAY,
    _retryable_ddl_error,
    emit_rls_policies,
)

LOCK_TIMEOUT = _DDL_LOCK_TIMEOUT
ATTEMPTS = _DDL_ATTEMPTS
RETRY_DELAY = _DDL_RETRY_DELAY

#: The unprivileged role RLS is verified against, and its throwaway password.
#: Shared here so the RLS suite and the compliance collectors describe the same
#: schema instead of each building their own.
APP_ROLE = "jdlib_rls_app"
APP_PASSWORD = "rls-test"

_TERMINATE_IDLE = sa.text(
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
    "WHERE datname = current_database() "
    "AND pid <> pg_backend_pid() "
    "AND state = 'idle in transaction'"
)


async def ensure_rls_role(engine: AsyncEngine, schema: str, app_role: str = APP_ROLE) -> str:
    """Create the unprivileged application role and grant it the tenant schema."""
    async with engine.begin() as connection:
        await connection.execute(
            sa.text(
                f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{app_role}') "
                f"THEN CREATE ROLE {app_role} LOGIN PASSWORD '{APP_PASSWORD}' NOBYPASSRLS; "
                "END IF; END $$;"
            )
        )
        await connection.execute(sa.text(f'GRANT USAGE ON SCHEMA "{schema}" TO {app_role}'))
        await connection.execute(
            sa.text(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "
                f'"{schema}" TO {app_role}'
            )
        )
        await connection.execute(
            sa.text(
                f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "{schema}" TO {app_role}'
            )
        )
    return app_role


def emit_tenant_policies(sync: sa.Connection, schema: str, app_role: str = APP_ROLE) -> None:
    """Emit the tenant isolation policies onto the schema a connection is bound to."""
    sync.execute(sa.text(f'SET search_path TO "{schema}"'))
    emit_rls_policies(sync, metadata=TenantBase.metadata, app_role=app_role)


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
            if attempt + 1 >= ATTEMPTS or not _retryable_ddl_error(exc):
                raise
            await asyncio.sleep(RETRY_DELAY * (attempt + 1))
