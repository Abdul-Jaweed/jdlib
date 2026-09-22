import pytest

from jdlib.authz.permissions import BUILTIN_PERMISSIONS, Permission, PermissionCatalog  # noqa: F401
from jdlib.control.enums import ScopeType
from jdlib.errors import UnknownPermission


def test_builtin_catalog_codes_are_frozen():
    catalog = PermissionCatalog.with_builtins()
    codes = {permission.code for permission in catalog.all()}
    assert {
        "tenant:read",
        "tenant:manage",
        "member:invite",
        "member:manage",
        "role:manage",
        "org:manage",
        "team:manage",
        "audit:read",
        "resource:read",
        "resource:create",
        "resource:update",
        "resource:delete",
        "resource:share",
    } == codes


def test_allowed_scopes_match_the_frozen_matrix():
    catalog = PermissionCatalog.with_builtins()
    assert catalog.validate("tenant:manage").allowed_scopes == frozenset({ScopeType.TENANT})
    assert catalog.validate("org:manage").allowed_scopes == frozenset(
        {ScopeType.TENANT, ScopeType.ORG}
    )
    assert catalog.validate("team:manage").allowed_scopes == frozenset(
        {ScopeType.TENANT, ScopeType.ORG, ScopeType.TEAM}
    )
    assert catalog.validate("resource:read").allowed_scopes == frozenset(
        {ScopeType.TENANT, ScopeType.ORG, ScopeType.TEAM}
    )


def test_unknown_permission_raises():
    with pytest.raises(UnknownPermission):
        PermissionCatalog.with_builtins().validate("invoice:approve")


def test_duplicate_registration_raises():
    catalog = PermissionCatalog.with_builtins()
    with pytest.raises(ValueError):
        catalog.register(Permission("tenant:read", "tenant", frozenset({ScopeType.TENANT}), "dup"))


def test_custom_registration_and_namespace():
    catalog = PermissionCatalog.with_builtins()
    catalog.register(
        Permission(
            "invoice:approve",
            "invoice",
            frozenset({ScopeType.TENANT, ScopeType.ORG, ScopeType.TEAM}),
            "Approve an invoice",
        )
    )
    assert catalog.validate("invoice:approve").namespace == "invoice"
    assert "invoice:approve" in {permission.code for permission in catalog.all()}
