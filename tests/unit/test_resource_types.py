import pytest

from jdlib.authz.permissions import Permission, PermissionCatalog
from jdlib.authz.resource_types import ResourceTypeDefinition, ResourceTypeRegistry
from jdlib.control.enums import ScopeType
from jdlib.errors import InvalidResourcePermission, UnknownResourceType
from tests.support.invoice import Invoice


def _definition(**overrides: object) -> ResourceTypeDefinition:
    base = {
        "resource_type": "invoice",
        "model": Invoice,
        "tenant_owned": True,
        "tenant_routed": True,
        "permission_namespace": "invoice",
    }
    base.update(overrides)
    return ResourceTypeDefinition(**base)  # type: ignore[arg-type]


def test_definition_rejects_routed_without_owned():
    with pytest.raises(ValueError):
        _definition(tenant_owned=False, tenant_routed=True)


def test_registry_duplicate_and_unknown():
    registry = ResourceTypeRegistry()
    registry.register(_definition())
    assert registry.get("invoice").model is Invoice
    with pytest.raises(ValueError):
        registry.register(_definition())
    with pytest.raises(UnknownResourceType):
        registry.get("mystery")


def test_permission_namespace_must_match():
    registry = ResourceTypeRegistry()
    registry.register(_definition())
    catalog = PermissionCatalog.with_builtins()
    catalog.register(
        Permission(
            "invoice:approve",
            "invoice",
            frozenset({ScopeType.TENANT, ScopeType.ORG, ScopeType.TEAM}),
            "Approve",
        )
    )
    registry.validate_permission("invoice", "invoice:approve", catalog)
    with pytest.raises(InvalidResourcePermission):
        registry.validate_permission("invoice", "resource:read", catalog)
