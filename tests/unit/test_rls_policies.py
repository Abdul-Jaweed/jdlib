from __future__ import annotations

from jdlib.models.base import TenantBase
from jdlib.persistence.strategies.rls import rls_eligible_tables


def test_rls_eligible_tables_covers_tenant_routed_models():
    import jdlib.models.audit  # noqa: F401
    import jdlib.models.org  # noqa: F401
    import jdlib.models.settings  # noqa: F401
    from tests.support.invoice import Invoice  # noqa: F401

    tables = set(rls_eligible_tables(TenantBase.metadata))
    assert {"organizations", "teams", "tenant_settings", "audit_events", "invoices"} <= tables
