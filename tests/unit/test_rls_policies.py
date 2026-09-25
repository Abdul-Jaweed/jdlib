from __future__ import annotations

import pytest
import sqlalchemy as sa

from jdlib.errors import StrategyCapabilityError
from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.rls import (
    emit_rls_policies,
    rls_eligible_tables,
    verify_rls,
)


def test_rls_eligible_tables_covers_tenant_routed_models():
    import jdlib.models.audit  # noqa: F401
    import jdlib.models.org  # noqa: F401
    import jdlib.models.settings  # noqa: F401
    from tests.support.invoice import Invoice  # noqa: F401

    tables = set(rls_eligible_tables(TenantBase.metadata))
    assert {"organizations", "teams", "tenant_settings", "audit_events", "invoices"} <= tables


def test_rls_eligible_tables_can_be_scoped_to_the_tables_a_database_has():
    """The eligible set is process-global, so a caller says which tables it means.

    It is derived from `TenantRouted.__subclasses__()`: this suite's own `invoices` double, a plugin
    or a second application in the same process all add to it. A caller whose database does not
    contain those tables cannot install policies at all -- the DDL is emitted for every eligible
    table and `verify_rls` then refuses the unprovisioned ones -- so the scope is how it narrows the
    set to its own. Names outside the eligible set are not invented, and an empty scope means no
    tables rather than all of them.
    """
    import jdlib.models.org  # noqa: F401
    from tests.support.invoice import Invoice  # noqa: F401

    assert "invoices" in rls_eligible_tables(TenantBase.metadata)

    scoped = rls_eligible_tables(TenantBase.metadata, tables=["teams", "invoices"])
    assert scoped == ("invoices", "teams")
    assert "organizations" not in scoped
    assert rls_eligible_tables(TenantBase.metadata, tables=["not_a_table"]) == ()
    assert rls_eligible_tables(TenantBase.metadata, tables=[]) == ()


class _RecordingConnection:
    """A sync connection that keeps the DDL it was asked to run."""

    def __init__(self) -> None:
        self.statements: list[str] = []
        self.dialect = sa.dialects.postgresql.dialect()

    def execute(self, statement: object, params: object = None) -> None:
        self.statements.append(str(statement))


def test_emit_rls_policies_emits_only_for_the_scoped_tables():
    """The scope is not decoration: it is what the emission loop reads."""
    import jdlib.models.org  # noqa: F401
    from tests.support.invoice import Invoice  # noqa: F401

    connection = _RecordingConnection()
    emit_rls_policies(
        connection,  # type: ignore[arg-type]
        metadata=TenantBase.metadata,
        app_role="app_role",
        tables=["teams"],
    )

    altered = [s for s in connection.statements if s.startswith("ALTER TABLE")]
    assert altered == [
        "ALTER TABLE teams ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE teams FORCE ROW LEVEL SECURITY",
    ]
    assert not any("invoices" in statement for statement in connection.statements)


class _FakeResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def one_or_none(self) -> object:
        return self._value


class _FakeConnection:
    async def __aenter__(self) -> _FakeConnection:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def execute(self, statement: object, params: object = None) -> _FakeResult:
        if "rolbypassrls" in str(statement):
            return _FakeResult((False, False))
        return _FakeResult(None)


class _FakeEngine:
    def connect(self) -> _FakeConnection:
        return _FakeConnection()


async def test_verify_rls_missing_table_hints_schema_binding():
    import jdlib.models.audit  # noqa: F401
    import jdlib.models.org  # noqa: F401
    import jdlib.models.settings  # noqa: F401
    from tests.support.invoice import Invoice  # noqa: F401

    with pytest.raises(StrategyCapabilityError, match="bound to the target schema"):
        await verify_rls(_FakeEngine(), "app_role", metadata=TenantBase.metadata)  # type: ignore[arg-type]
