from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from jdlib.errors import StrategyCapabilityError
from jdlib.models.base import TenantRouted

_DDL_LOCK_TIMEOUT = "5s"
_DDL_ATTEMPTS = 3
_DDL_RETRY_DELAY = 0.25
_RETRYABLE_DDL_ERRORS = {"DeadlockDetectedError", "LockNotAvailableError"}

_POLICY = (
    "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) "
    "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)"
)

_TABLE_CHECK = sa.text(
    """
    SELECT c.relrowsecurity,
           c.relforcerowsecurity,
           EXISTS (
               SELECT 1
               FROM pg_policies p
               WHERE p.schemaname = n.nspname
                 AND p.tablename = c.relname
                 AND p.policyname = 'tenant_isolation'
           ) AS has_policy
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.oid = to_regclass(:name)
    """
)


def rls_eligible_tables(
    metadata: sa.MetaData, *, tables: Iterable[str] | None = None
) -> tuple[str, ...]:
    """The tenant-routed tables on ``metadata``, optionally narrowed to ``tables``.

    The set comes from ``TenantRouted.__subclasses__()``, which is **process-global**: a test
    double, a plugin or a second application imported into the same interpreter adds its tables to
    every caller's eligible set. A caller whose database does not contain those tables cannot
    install policies at all -- the DDL is emitted for each eligible table, and the verification then
    refuses the ones that are not there -- so ``tables`` is how such a caller says which tables it
    means. Names outside the eligible set are not invented, and an empty scope means *no* tables
    rather than all of them.
    """
    found: list[str] = []

    def walk(cls: type) -> None:
        for subclass in cls.__subclasses__():
            table = getattr(subclass, "__table__", None)
            if table is not None and table.metadata is metadata:
                found.append(table.name)
            walk(subclass)

    walk(TenantRouted)
    eligible = tuple(sorted(set(found)))
    if tables is None:
        return eligible
    wanted = set(tables)
    return tuple(name for name in eligible if name in wanted)


def emit_rls_policies(
    connection: sa.Connection,
    *,
    metadata: sa.MetaData,
    app_role: str | None = None,
    tables: Iterable[str] | None = None,
) -> None:
    for name in rls_eligible_tables(metadata, tables=tables):
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


def _retryable_ddl_error(exc: BaseException) -> bool:
    """Whether a DDL failure is a transient lock conflict worth retrying."""
    names = {type(exc).__name__}
    orig = getattr(exc, "orig", None)
    if orig is not None:
        names.add(type(orig).__name__)
    return bool(names & _RETRYABLE_DDL_ERRORS)


async def install_rls(
    engine: AsyncEngine,
    *,
    metadata: sa.MetaData,
    app_role: str,
    tables: Iterable[str] | None = None,
) -> None:
    """Emit and verify RLS policies, retrying transient lock conflicts.

    The DDL takes ``ACCESS EXCLUSIVE`` locks; a live deployment or a lingering
    pooled connection can deadlock or hold the lock past ``lock_timeout``.
    Three bounded attempts (with a small backoff) keep migrations from
    flaking while still failing closed on a real lock holder.

    Assumes PostgreSQL transactional DDL: a failed attempt rolls back
    atomically, and the policy set is emitted idempotently (``DROP POLICY IF
    EXISTS`` + ``CREATE POLICY``), so a retry re-runs the whole emission
    without duplicating policies.

    ``tables`` narrows the eligible set (see :func:`rls_eligible_tables`); the default keeps the
    previous behaviour, which is every tenant-routed table the process knows about.
    """
    for attempt in range(_DDL_ATTEMPTS):
        try:
            async with engine.begin() as connection:
                await connection.execute(
                    sa.text(f"SET LOCAL lock_timeout = '{_DDL_LOCK_TIMEOUT}'")
                )
                await connection.run_sync(
                    lambda sync: emit_rls_policies(
                        sync, metadata=metadata, app_role=app_role, tables=tables
                    )
                )
            break
        except Exception as exc:
            if attempt + 1 >= _DDL_ATTEMPTS or not _retryable_ddl_error(exc):
                raise
            await asyncio.sleep(_DDL_RETRY_DELAY * (attempt + 1))
    await verify_rls(engine, app_role, metadata=metadata, tables=tables)


@dataclass(frozen=True, slots=True)
class RlsInspection:
    """What the PostgreSQL catalog says about tenant isolation on one schema.

    Reading and judging are separate concerns: :func:`verify_rls` raises on the
    first problem, while evidence has to report *all* of them, and both must agree
    on what they saw. They therefore share this inspection rather than each asking
    the catalog their own question.
    """

    tables_checked: tuple[str, ...]
    tables_enforced: tuple[str, ...]
    tables_missing_rls: tuple[str, ...]
    tables_missing_force: tuple[str, ...]
    tables_missing_policy: tuple[str, ...]
    tables_unprovisioned: tuple[str, ...]

    @property
    def is_enforced(self) -> bool:
        """Whether every tenant-routed table is provisioned, forced and policied."""
        return not (
            self.tables_missing_rls
            or self.tables_missing_force
            or self.tables_missing_policy
            or self.tables_unprovisioned
        )


async def inspect_rls(
    engine: AsyncEngine, *, metadata: sa.MetaData, tables: Iterable[str] | None = None
) -> RlsInspection:
    """Inspect row-level security on the schema this engine is bound to.

    Neither role checks nor judgement: a table the engine cannot see is reported as
    unprovisioned, because for evidence that is an observation, and for a caller
    who asked for a schema it is a failure it can explain.
    """
    eligible = rls_eligible_tables(metadata, tables=tables)
    missing_rls: list[str] = []
    missing_force: list[str] = []
    missing_policy: list[str] = []
    unprovisioned: list[str] = []
    enforced: list[str] = []
    async with engine.connect() as connection:
        for name in eligible:
            row = (await connection.execute(_TABLE_CHECK, {"name": name})).one_or_none()
            if row is None:
                unprovisioned.append(name)
                continue
            rowsecurity, force, has_policy = bool(row[0]), bool(row[1]), bool(row[2])
            if not rowsecurity:
                missing_rls.append(name)
            elif not force:
                missing_force.append(name)
            if not has_policy:
                missing_policy.append(name)
            if rowsecurity and force and has_policy:
                enforced.append(name)
    return RlsInspection(
        tables_checked=eligible,
        tables_enforced=tuple(enforced),
        tables_missing_rls=tuple(missing_rls),
        tables_missing_force=tuple(missing_force),
        tables_missing_policy=tuple(missing_policy),
        tables_unprovisioned=tuple(unprovisioned),
    )


async def verify_rls(
    engine: AsyncEngine,
    app_role: str,
    *,
    metadata: sa.MetaData,
    tables: Iterable[str] | None = None,
) -> None:
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
    inspection = await inspect_rls(engine, metadata=metadata, tables=tables)
    for name in inspection.tables_unprovisioned:
        raise StrategyCapabilityError(
            f"RLS table missing or not visible: {name}; "
            "the engine must be bound to the target schema (search_path)"
        )
    for name in (*inspection.tables_missing_rls, *inspection.tables_missing_force):
        raise StrategyCapabilityError(f"RLS is not forced on table {name}")
    for name in inspection.tables_missing_policy:
        raise StrategyCapabilityError(f"RLS table {name} lacks tenant_isolation policy")
