from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from jdlib.errors import StrategyCapabilityError
from jdlib.models.base import TenantRouted

_POLICY = (
    "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) "
    "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)"
)


def rls_eligible_tables(metadata: sa.MetaData) -> tuple[str, ...]:
    found: list[str] = []

    def walk(cls: type) -> None:
        for subclass in cls.__subclasses__():
            table = getattr(subclass, "__table__", None)
            if table is not None and table.metadata is metadata:
                found.append(table.name)
            walk(subclass)

    walk(TenantRouted)
    return tuple(sorted(set(found)))


def emit_rls_policies(
    connection: sa.Connection, *, metadata: sa.MetaData, app_role: str | None = None
) -> None:
    for name in rls_eligible_tables(metadata):
        quoted = connection.dialect.identifier_preparer.quote(name)
        connection.execute(sa.text(f"ALTER TABLE {quoted} ENABLE ROW LEVEL SECURITY"))
        connection.execute(sa.text(f"ALTER TABLE {quoted} FORCE ROW LEVEL SECURITY"))
        connection.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {quoted}"))
        connection.execute(sa.text(f"CREATE POLICY tenant_isolation ON {quoted} {_POLICY}"))
        if app_role:
            role = connection.dialect.identifier_preparer.quote(app_role)
            connection.execute(
                sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {quoted} TO {role}")
            )


async def verify_rls(engine: AsyncEngine, app_role: str) -> None:
    async with engine.connect() as connection:
        role = (
            await connection.execute(
                sa.text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = :name"),
                {"name": app_role},
            )
        ).one_or_none()
    if role is None:
        raise StrategyCapabilityError(f"RLS app role does not exist: {app_role}")
    bypass, is_super = role
    if bypass or is_super:
        raise StrategyCapabilityError(f"RLS app role {app_role} can bypass row level security")
