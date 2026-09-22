from __future__ import annotations

from dataclasses import dataclass

from jdlib.authz.permissions import PermissionCatalog
from jdlib.errors import InvalidResourcePermission, UnknownResourceType


@dataclass(frozen=True, slots=True)
class ResourceTypeDefinition:
    resource_type: str
    model: type
    tenant_owned: bool
    tenant_routed: bool
    permission_namespace: str

    def __post_init__(self) -> None:
        if not self.resource_type or not self.permission_namespace:
            raise ValueError("resource_type and permission_namespace are required")
        if self.tenant_routed and not self.tenant_owned:
            raise ValueError("tenant_routed requires tenant_owned")
        if self.tenant_routed and not (
            hasattr(self.model, "organization_id") and hasattr(self.model, "team_id")
        ):
            raise ValueError(
                "tenant_routed requires a model with organization_id and team_id"
            )


class ResourceTypeRegistry:
    def __init__(self) -> None:
        self._by_name: dict[str, ResourceTypeDefinition] = {}

    def register(self, definition: ResourceTypeDefinition) -> None:
        if definition.resource_type in self._by_name:
            raise ValueError(f"resource type already registered: {definition.resource_type}")
        self._by_name[definition.resource_type] = definition

    def get(self, resource_type: str) -> ResourceTypeDefinition:
        definition = self._by_name.get(resource_type)
        if definition is None:
            raise UnknownResourceType(resource_type)
        return definition

    def all(self) -> tuple[ResourceTypeDefinition, ...]:
        return tuple(self._by_name.values())

    def validate_permission(
        self, resource_type: str, permission_code: str, catalog: PermissionCatalog
    ) -> None:
        definition = self.get(resource_type)
        permission = catalog.validate(permission_code)
        if permission.namespace != definition.permission_namespace:
            raise InvalidResourcePermission(
                f"{permission_code} is not valid for resource type {resource_type}"
            )
