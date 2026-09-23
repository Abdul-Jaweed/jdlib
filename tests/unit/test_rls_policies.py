from __future__ import annotations

import pytest

from jdlib.errors import StrategyCapabilityError
from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.rls import rls_eligible_tables, verify_rls


def test_rls_eligible_tables_covers_tenant_routed_models():
    import jdlib.models.audit  # noqa: F401
    import jdlib.models.org  # noqa: F401
    import jdlib.models.settings  # noqa: F401
    from tests.support.invoice import Invoice  # noqa: F401

    tables = set(rls_eligible_tables(TenantBase.metadata))
    assert {"organizations", "teams", "tenant_settings", "audit_events", "invoices"} <= tables


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
