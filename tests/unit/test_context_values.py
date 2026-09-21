import dataclasses
import uuid

import pytest

from jdlib.context import (
    Principal,
    PrincipalKind,
    TenantContext,
    TenantRecord,
    TenantRef,
    context_scope,
    current_principal,
    current_privilege,
    current_tenant,
    scoped_key,
)
from jdlib.control.enums import PlacementStrategy, TenantStatus
from jdlib.errors import MissingTenantContext


def _context() -> TenantContext:
    return TenantContext(
        tenant_id=uuid.UUID("00000000-0000-0000-0000-0000000000aa"),
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=uuid.uuid4()),
        request_id="req-1",
        correlation_id="corr-1",
    )


def test_accessors_fail_closed_without_context():
    with pytest.raises(MissingTenantContext):
        current_tenant()
    with pytest.raises(MissingTenantContext):
        current_principal()
    with pytest.raises(MissingTenantContext):
        current_privilege()
    with pytest.raises(MissingTenantContext):
        scoped_key("cache", "x")


def test_context_scope_installs_and_clears():
    context = _context()
    with context_scope(context):
        assert current_tenant() is context
        assert current_principal() is context.principal
        assert current_privilege() is None
    with pytest.raises(MissingTenantContext):
        current_tenant()


def test_value_objects_are_frozen():
    context = _context()
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.tenant_id = uuid.uuid4()  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.principal.kind = PrincipalKind.SERVICE_ACCOUNT  # type: ignore[misc]


def test_scoped_key_is_versioned_and_encoded():
    with context_scope(_context()):
        assert scoped_key("cache") == "jdlib:v1:00000000-0000-0000-0000-0000000000aa:cache"
        assert (
            scoped_key("cache", "a:b", "c")
            == "jdlib:v1:00000000-0000-0000-0000-0000000000aa:cache:a%3Ab:c"
        )
        assert scoped_key("cache", "a", "b:c") != scoped_key("cache", "a:b", "c")


def test_tenant_ref_and_record_shapes():
    ref = TenantRef(slug="acme")
    record = TenantRecord(
        id=uuid.uuid4(), slug="acme", status=TenantStatus.ACTIVE, strategy=PlacementStrategy.SHARED
    )
    assert ref.id is None
    assert record.status is TenantStatus.ACTIVE
