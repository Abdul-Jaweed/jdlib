from __future__ import annotations

from dataclasses import dataclass

from jdlib.control.enums import ScopeType
from jdlib.errors import UnknownPermission


@dataclass(frozen=True, slots=True)
class Permission:
    code: str
    namespace: str
    allowed_scopes: frozenset[ScopeType]
    description: str


def _permission(
    code: str, namespace: str, scopes: set[ScopeType], description: str
) -> Permission:
    return Permission(code, namespace, frozenset(scopes), description)


_TENANT = {ScopeType.TENANT}
_TENANT_ORG = {ScopeType.TENANT, ScopeType.ORG}
_ANY_SCOPE = {ScopeType.TENANT, ScopeType.ORG, ScopeType.TEAM}

BUILTIN_PERMISSIONS: tuple[Permission, ...] = (
    _permission("tenant:read", "tenant", _TENANT, "Read tenant metadata"),
    _permission("tenant:manage", "tenant", _TENANT, "Manage tenant lifecycle settings"),
    _permission("member:invite", "member", _TENANT, "Invite members"),
    _permission("member:manage", "member", _TENANT, "Manage memberships"),
    _permission("role:manage", "role", _TENANT, "Manage roles and bindings"),
    _permission("org:manage", "org", _TENANT_ORG, "Manage organizations"),
    _permission("team:manage", "team", _ANY_SCOPE, "Manage teams"),
    _permission("audit:read", "audit", _TENANT, "Read audit events"),
    _permission("resource:read", "resource", _ANY_SCOPE, "Read resources"),
    _permission("resource:create", "resource", _ANY_SCOPE, "Create resources"),
    _permission("resource:update", "resource", _ANY_SCOPE, "Update resources"),
    _permission("resource:delete", "resource", _ANY_SCOPE, "Delete resources"),
    _permission("resource:share", "resource", _ANY_SCOPE, "Share resources"),
)


class PermissionCatalog:
    def __init__(self, permissions: tuple[Permission, ...] = ()) -> None:
        self._by_code: dict[str, Permission] = {}
        for permission in permissions:
            self.register(permission)

    @classmethod
    def with_builtins(cls) -> PermissionCatalog:
        return cls(BUILTIN_PERMISSIONS)

    def register(self, permission: Permission) -> None:
        if permission.code in self._by_code:
            raise ValueError(f"permission already registered: {permission.code}")
        self._by_code[permission.code] = permission

    def validate(self, code: str) -> Permission:
        permission = self._by_code.get(code)
        if permission is None:
            raise UnknownPermission(code)
        return permission

    def all(self) -> tuple[Permission, ...]:
        return tuple(self._by_code.values())
