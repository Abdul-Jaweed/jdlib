import subprocess
import sys
import uuid
from datetime import UTC, datetime

import pytest

from jdlib.context import Principal, PrincipalKind, PrivilegeContext, PrivilegeKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.errors import TenantNotWritable
from jdlib.models import audit, org, settings  # noqa: F401
from jdlib.models.base import TenantRouted
from jdlib.persistence.models import (
    NullWriteFence,
    privileged_bypass,
    tenant_table_map,
)

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _context(privilege: PrivilegeContext | None = None) -> TenantContext:
    return TenantContext(
        tenant_id=TENANT_ID,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req",
        correlation_id="corr",
        privilege=privilege,
    )


def test_tenant_table_map_covers_framework_tenant_plane():
    tables = tenant_table_map()
    assert {"organizations", "teams", "tenant_settings", "audit_events"} <= set(tables)
    assert all(issubclass(model, TenantRouted) for model in tables.values())


def test_tenant_table_map_bootstraps_framework_models():
    code = (
        "from jdlib.persistence.models import tenant_table_map\n"
        "tables = tenant_table_map()\n"
        "expected = {'organizations', 'teams', 'tenant_settings', 'audit_events'}\n"
        "assert expected <= set(tables), sorted(tables)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


async def test_null_write_fence_always_allows():
    await NullWriteFence().assert_writable(TENANT_ID)


def test_privileged_bypass_requires_system_relocation_capability():
    assert privileged_bypass(_context()) is False
    operator = PrivilegeContext(
        kind=PrivilegeKind.OPERATOR,
        capability="relocation.manage",
        justification="ticket",
        actor=Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4()),
        issued_at=datetime.now(UTC),
        expires_at=None,
    )
    assert privileged_bypass(_context(operator)) is False
    system = PrivilegeContext(
        kind=PrivilegeKind.SYSTEM,
        capability="relocation.manage",
        justification=None,
        actor=Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4()),
        issued_at=datetime.now(UTC),
        expires_at=None,
    )
    assert privileged_bypass(_context(system)) is True
    other_capability = PrivilegeContext(
        kind=PrivilegeKind.SYSTEM,
        capability="tenant.migrate",
        justification=None,
        actor=Principal(kind=PrincipalKind.PLATFORM_OPERATOR, id=uuid.uuid4()),
        issued_at=datetime.now(UTC),
        expires_at=None,
    )
    assert privileged_bypass(_context(other_capability)) is False
    test_kind = PrivilegeContext(
        kind=PrivilegeKind.TEST,
        capability=None,
        justification=None,
        actor=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        issued_at=datetime.now(UTC),
        expires_at=None,
    )
    assert privileged_bypass(_context(test_kind)) is False


class _FencedFence:
    async def assert_writable(self, tenant_id: uuid.UUID) -> None:
        raise TenantNotWritable("relocation in progress")


async def test_fence_raises_for_non_privileged_context():
    with pytest.raises(TenantNotWritable):
        await _FencedFence().assert_writable(TENANT_ID)
