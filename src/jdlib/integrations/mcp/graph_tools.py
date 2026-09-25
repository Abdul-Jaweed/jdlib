"""The graph's tools, as declarations (directive §22).

§22 asks for meaningful production tools and warns against exposing low-level operations blindly.
These are the repository's own operations, one tool each, and the two rules §19 and §22 imply are
enforced by construction rather than by review:

* **no schema has anywhere to put an identity.** There is no `tenant_id`, no `user_id`, no `roles`:
  the handler reads the ambient security context the invocation established, and the repository
  takes the tenant from that context. A caller cannot name a tenant because the call has no slot
  for one;
* **no schema has anywhere to put a statement.** Arbitrary Cypher is not a tool — a tool that took
  a query string would have no schema worth the name. A caller's text reaches the database only
  through the identifier positions the graph validates (`Label`, `RelationshipType`, `PropertyKey`),
  which is the same door every other caller uses.

Capabilities split along the line the directive draws. Reading needs `graph:read`; writing needs
`graph:write`. A single tool that could do both would have to declare the stronger capability, so
the surface keeps them apart and the weaker one stays usable on its own.

`graph_search` is deliberately absent. The repository has no property search, and a tool that took
property *names* from a caller would re-open exactly the identifier-position class the adversarial
work closed. §22's own words — *do NOT expose every low-level operation blindly* — are the licence
for a smaller surface, and the capability page records the absence as a decision.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from jdlib.graph.repository import GraphRepository
from jdlib.integrations.mcp.tools import McpTool
from jdlib.security.context import current_security_context

#: What reading the graph requires. Kept apart from the writing capability on purpose.
READ_CAPABILITY = "graph:read"

#: What changing the graph requires.
WRITE_CAPABILITY = "graph:write"


def _schema(
    properties: Mapping[str, str], required: tuple[str, ...]
) -> dict[str, object]:
    """A schema that closes itself: only the declared arguments, all of them typed."""
    return {
        "type": "object",
        "properties": {name: {"type": kind} for name, kind in properties.items()},
        "required": list(required),
        "additionalProperties": False,
    }


def _handler(repository: GraphRepository, operation: str) -> Callable[..., Any]:
    """One tool's handler: the ambient context, the declared operation, nothing else.

    The context is read here rather than passed in because the invocation established it a moment
    earlier — and because a parameter is a thing a caller can supply.
    """

    async def handler(**arguments: Any) -> Any:
        context = current_security_context()
        return await getattr(repository, operation)(context=context, **arguments)

    return handler


def graph_tools(repository: GraphRepository) -> tuple[McpTool, ...]:
    """The graph's tools over ``repository``, in the order the registry will sort them."""
    node = {"label": "string", "node_id": "string"}
    edge = {
        "relationship": "string",
        "from_label": "string",
        "from_id": "string",
        "to_label": "string",
        "to_id": "string",
    }
    return (
        McpTool(
            name="graph_get",
            description="Read one node of this tenant's graph.",
            handler=_handler(repository, "get_node"),
            capability=READ_CAPABILITY,
            resource_kind="graph_node",
            action="read",
            input_schema=_schema(node, ("label", "node_id")),
        ),
        McpTool(
            name="graph_create",
            description="Create one node in this tenant's graph.",
            handler=_handler(repository, "create_node"),
            capability=WRITE_CAPABILITY,
            resource_kind="graph_node",
            action="create",
            input_schema=_schema({**node, "properties": "object"}, ("label", "node_id")),
        ),
        McpTool(
            name="graph_update",
            description="Merge properties into one node of this tenant's graph.",
            handler=_handler(repository, "update_node"),
            capability=WRITE_CAPABILITY,
            resource_kind="graph_node",
            action="update",
            input_schema=_schema(
                {**node, "properties": "object"}, ("label", "node_id", "properties")
            ),
        ),
        McpTool(
            name="graph_delete",
            description="Delete one node of this tenant's graph.",
            handler=_handler(repository, "delete_node"),
            capability=WRITE_CAPABILITY,
            resource_kind="graph_node",
            action="delete",
            input_schema=_schema(node, ("label", "node_id")),
        ),
        McpTool(
            name="graph_relate",
            description="Create one edge between two nodes of this tenant's graph.",
            handler=_handler(repository, "relate"),
            capability=WRITE_CAPABILITY,
            resource_kind="graph_edge",
            action="create",
            input_schema=_schema({**edge, "properties": "object"}, tuple(edge)),
        ),
        McpTool(
            name="graph_related",
            description="Answer whether this tenant's graph has one edge.",
            handler=_handler(repository, "related"),
            capability=READ_CAPABILITY,
            resource_kind="graph_edge",
            action="read",
            input_schema=_schema(edge, tuple(edge)),
        ),
        McpTool(
            name="graph_unrelate",
            description="Delete one edge of this tenant's graph.",
            handler=_handler(repository, "unrelate"),
            capability=WRITE_CAPABILITY,
            resource_kind="graph_edge",
            action="delete",
            input_schema=_schema(edge, tuple(edge)),
        ),
    )
