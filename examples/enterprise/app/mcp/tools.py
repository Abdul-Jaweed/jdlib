"""The resource plane as tools: three declarations, and the capability none of them can omit.

An MCP tool is a *declaration*: a name, a closed input schema, the capability it needs, and a
handler. Three properties are the point, and each is checked rather than reviewed:

* **no schema has anywhere to put an identity.** There is no `tenant_id`, no `user_id`, no `roles`:
  the handler reads the ambient security context the invocation established, and the service takes
  the tenant from that context. A caller cannot name a tenant because the call has no slot for one.
* **no schema has anywhere to put a statement.** These tools call the service; they do not take a
  query, a table name or a filter expression.
* **the capability is part of the declaration.** `resource:read` and `resource:write` are the same
  strings the HTTP routes declare and the policy files are written against, so a tool cannot be
  reachable without an authorization answer — the registry refuses a tool that declares none.

The handlers return wire shapes rather than ORM rows: what a client receives is a contract, and an
ORM object's attributes are not.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from examples.enterprise.app.services.resources import ResourceService
from jdlib.integrations.mcp.tools import McpTool
from jdlib.security.context import current_security_context

__all__ = ["READ_CAPABILITY", "WRITE_CAPABILITY", "resource_tools"]

#: What reading the resource plane requires — the string `app/api/resources.py` declares and
#: `config/cerbos/policies/` is written against.
READ_CAPABILITY = "resource:read"

#: What changing it requires.
WRITE_CAPABILITY = "resource:write"


def _schema(properties: Mapping[str, str], required: tuple[str, ...]) -> dict[str, object]:
    """A schema that closes itself: only the declared arguments, all of them typed."""
    return {
        "type": "object",
        "properties": {name: {"type": kind} for name, kind in properties.items()},
        "required": list(required),
        "additionalProperties": False,
    }


def _row(resource: Any) -> dict[str, Any]:
    """The wire shape of one resource."""
    return {
        "id": str(resource.id),
        "name": resource.name,
        "kind": resource.kind,
        "status": resource.status,
    }


def resource_tools(service: ResourceService) -> tuple[McpTool, ...]:
    """The resource plane's tools over ``service``, in the order the registry sorts them."""

    async def get_resource(**arguments: Any) -> Any:
        context = current_security_context().require_tenant()
        resource = await service.get(context, uuid.UUID(str(arguments["resource_id"])))
        # Another tenant's resource is not "forbidden" here: it does not exist for this caller, and
        # saying which it is would confirm the id belongs to somebody.
        return None if resource is None else _row(resource)

    async def list_resources(**arguments: Any) -> Any:
        context = current_security_context().require_tenant()
        rows = await service.list(
            context,
            limit=int(arguments.get("limit", 50)),
            offset=int(arguments.get("offset", 0)),
        )
        return [_row(row) for row in rows]

    async def archive_resource(**arguments: Any) -> Any:
        context = current_security_context().require_tenant()
        resource = await service.archive(context, uuid.UUID(str(arguments["resource_id"])))
        return _row(resource)

    return (
        McpTool(
            name="resource_get",
            description="Read one resource of the caller's tenant.",
            handler=get_resource,
            capability=READ_CAPABILITY,
            resource_kind="resource",
            action="read",
            input_schema=_schema({"resource_id": "string"}, ("resource_id",)),
        ),
        McpTool(
            name="resource_list",
            description="List the caller's tenant's resources, newest first.",
            handler=list_resources,
            capability=READ_CAPABILITY,
            resource_kind="resource",
            action="list",
            input_schema=_schema({"limit": "integer", "offset": "integer"}, ()),
        ),
        McpTool(
            name="resource_archive",
            description="Archive one resource of the caller's tenant.",
            handler=archive_resource,
            capability=WRITE_CAPABILITY,
            resource_kind="resource",
            action="archive",
            input_schema=_schema({"resource_id": "string"}, ("resource_id",)),
        ),
    )
