"""The graph tools: what a caller may ask for, and what no tool may ever accept (directive §22).

§22 asks for meaningful production tools and then says the two things that keep them safe:
*do NOT expose every low-level operation blindly*, and *tool names and exact schemas should follow
the final JDLib MCP design*. So these tests pin the architecture rather than a call list:

* every tool declares a capability — none is public, because a graph tool with no requirement is
  a graph tool nobody authorized;
* **no tool accepts an identity.** Not `tenant_id`, not `user_id`, not `roles`, not a principal:
  §19's rule is that identity comes from the authenticated context, and the way to enforce it is
  for the schema to have nowhere to put one. The handler reads the ambient context the invocation
  established;
* **no tool accepts a statement.** Arbitrary Cypher is not a tool — §22 asks for schemas, and a
  tool that takes a query string has none. This is the same rule the repository already keeps, and
  the test is what stops it being re-opened by an MCP-shaped side door;
* the tenant is not a parameter anywhere: the repository takes it from the context, so a caller
  cannot name one and a tool cannot forward one.

The repository is a collaborator here, not the subject: the double records the context it was
handed, which is how "the ambient tenant, never an argument" becomes checkable.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from jdlib.errors import AuthenticationError
from jdlib.graph.errors import GraphValidationError
from jdlib.integrations.mcp.graph_tools import graph_tools
from jdlib.integrations.mcp.tools import McpTool, McpToolRegistry
from jdlib.security.context import current_security_context, security_context_scope
from tests.support.graph_fakes import graph_context

TENANT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")

#: Argument names that would let a caller assert an identity. §19: never trusted, never accepted.
IDENTITY_ARGUMENTS = {
    "tenant_id",
    "tenant",
    "user_id",
    "user",
    "principal",
    "principal_id",
    "roles",
    "role",
    "scopes",
    "scope",
    "authenticated",
    "actor",
    "actor_id",
    "subject",
}

#: Argument names that would let a caller supply a statement. §22: arbitrary Cypher is not a tool.
STATEMENT_ARGUMENTS = {"query", "cypher", "statement", "sql", "raw", "commands"}


class _Repository:
    """The collaborator: records what it was asked, with which context."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], Any]] = []
        self.node: dict[str, Any] | None = {"id": "u1", "name": "Ada"}
        self.relate_error: BaseException | None = None

    async def _record(self, name: str, kwargs: dict[str, Any]) -> Any:
        context = kwargs.pop("context")
        self.calls.append((name, kwargs, context))
        if name == "get_node":
            return self.node
        if name == "related":
            return True
        if name == "update_node":
            return True
        return None

    async def get_node(self, **kwargs: Any) -> Any:
        return await self._record("get_node", kwargs)

    async def create_node(self, **kwargs: Any) -> Any:
        return await self._record("create_node", kwargs)

    async def update_node(self, **kwargs: Any) -> Any:
        return await self._record("update_node", kwargs)

    async def delete_node(self, **kwargs: Any) -> Any:
        return await self._record("delete_node", kwargs)

    async def relate(self, **kwargs: Any) -> Any:
        if self.relate_error is not None:
            raise self.relate_error
        return await self._record("relate", kwargs)

    async def related(self, **kwargs: Any) -> Any:
        return await self._record("related", kwargs)

    async def unrelate(self, **kwargs: Any) -> Any:
        return await self._record("unrelate", kwargs)


def _registry() -> tuple[McpToolRegistry, _Repository]:
    repository = _Repository()
    registry = McpToolRegistry()
    for tool in graph_tools(repository):  # type: ignore[arg-type]
        registry.register(tool)
    return registry, repository


def _schema_arguments(tool: McpTool) -> set[str]:
    properties = tool.input_schema.get("properties", {})
    assert isinstance(properties, dict)
    return set(properties)


async def test_the_graph_tools_declare_capabilities_and_none_is_public() -> None:
    registry, _ = _registry()
    names = [tool.name for tool in registry.tools()]
    assert names == [
        "graph_create",
        "graph_delete",
        "graph_get",
        "graph_relate",
        "graph_related",
        "graph_unrelate",
        "graph_update",
    ]
    for tool in registry.tools():
        assert tool.public is False
        assert tool.capability, f"{tool.name} declares no capability"
        assert tool.resource_kind
        assert tool.action


async def test_no_tool_accepts_an_identity_it_was_not_given() -> None:
    """§19's rule at the schema level: there is nowhere to put a forged identity."""
    registry, _ = _registry()
    for tool in registry.tools():
        accepted = _schema_arguments(tool)
        forged = accepted & IDENTITY_ARGUMENTS
        assert not forged, f"{tool.name} accepts {forged}"


async def test_no_tool_accepts_a_statement() -> None:
    """Arbitrary Cypher is not a tool, however it is spelled."""
    registry, _ = _registry()
    for tool in registry.tools():
        accepted = _schema_arguments(tool)
        statements = accepted & STATEMENT_ARGUMENTS
        assert not statements, f"{tool.name} accepts {statements}"


async def test_every_tool_describes_itself_and_requires_what_it_needs() -> None:
    registry, _ = _registry()
    for tool in registry.tools():
        assert tool.description.strip(), f"{tool.name} has no description"
        schema = tool.input_schema
        assert schema.get("type") == "object"
        assert schema.get("additionalProperties") is False
        declared = schema.get("required", [])
        assert isinstance(declared, list)
        required = set(declared)
        assert required, f"{tool.name} requires nothing"
        assert required <= _schema_arguments(tool)


async def test_a_read_tool_reads_the_ambient_tenants_node() -> None:
    """The handler reads the context the invocation established — never an argument."""
    registry, repository = _registry()
    tool = registry.get("graph_get")
    with security_context_scope(graph_context(tenant_id=TENANT_ID)):
        assert current_security_context() is not None
        result = await tool.handler(label="User", node_id="u1")
    assert result == {"id": "u1", "name": "Ada"}
    name, kwargs, context = repository.calls[0]
    assert name == "get_node"
    assert kwargs == {"label": "User", "node_id": "u1"}
    assert context.tenant_id == TENANT_ID


async def test_a_write_tool_writes_under_the_ambient_context() -> None:
    registry, repository = _registry()
    tool = registry.get("graph_create")
    with security_context_scope(graph_context(tenant_id=TENANT_ID)):
        await tool.handler(label="User", node_id="u2", properties={"name": "Grace"})
    name, kwargs, context = repository.calls[0]
    assert name == "create_node"
    assert kwargs == {"label": "User", "node_id": "u2", "properties": {"name": "Grace"}}
    assert context.tenant_id == TENANT_ID


async def test_a_relation_tool_names_both_endpoints_and_the_edge() -> None:
    registry, repository = _registry()
    tool = registry.get("graph_relate")
    with security_context_scope(graph_context(tenant_id=TENANT_ID)):
        await tool.handler(
            relationship="FOLLOWS",
            from_label="User",
            from_id="u1",
            to_label="User",
            to_id="u2",
        )
    name, kwargs, _ = repository.calls[0]
    assert name == "relate"
    assert kwargs == {
        "relationship": "FOLLOWS",
        "from_label": "User",
        "from_id": "u1",
        "to_label": "User",
        "to_id": "u2",
    }


async def test_the_tools_do_not_swallow_the_librarys_refusals() -> None:
    """A label the vocabulary refuses reaches the caller as that refusal, not as a success."""
    registry, repository = _registry()
    repository.relate_error = GraphValidationError("a relationship type must be an identifier")
    tool = registry.get("graph_relate")
    scope = security_context_scope(graph_context(tenant_id=TENANT_ID))
    with scope, pytest.raises(GraphValidationError):
        await tool.handler(
            relationship="FOLLOWS) DETACH DELETE n //",
            from_label="User",
            from_id="u1",
            to_label="User",
            to_id="u2",
        )


async def test_a_read_tool_without_a_context_is_refused_rather_than_guessed() -> None:
    """No ambient context is a failure, not an anonymous read.

    The refusal is the library's own `AuthenticationError` — the class the context getter raises —
    not a fresh MCP-shaped one, so a caller can tell "nothing is active" from "the tool failed".
    """
    registry, _ = _registry()
    tool = registry.get("graph_get")
    with pytest.raises(AuthenticationError):
        await tool.handler(label="User", node_id="u1")
