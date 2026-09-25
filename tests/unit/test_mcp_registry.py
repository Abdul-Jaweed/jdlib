"""The MCP tool registry: a tool declares what it needs before it can exist (directive §20).

The directive's rule is blunt — *no tool should be implicitly public unless explicitly designed as
public* — and a rule enforced by review is not enforced. So the refusal lives in the type: a tool
either names the capability it requires, or says `public=True` in so many words, and a tool that
does neither cannot be constructed, let alone registered.

The registry is the inventory the programme's gate asks for: `inventory()` returns what is
registered with what each tool requires, so a test can assert that every production tool declares
a capability — and a tool added without one fails at import rather than at review.
"""

from __future__ import annotations

from typing import Any

import pytest

from jdlib.integrations.mcp.errors import McpToolDefinitionError
from jdlib.integrations.mcp.tools import McpTool, McpToolRegistry


async def _handler(**arguments: Any) -> dict[str, Any]:
    return {"ok": True, "arguments": arguments}


def _tool(**overrides: Any) -> McpTool:
    fields: dict[str, Any] = {
        "name": "graph_get",
        "description": "Read one node by identity, inside the caller's tenant.",
        "capability": "graph:read",
        "resource_kind": "graph_node",
        "action": "read",
        "handler": _handler,
    }
    fields.update(overrides)
    return McpTool(**fields)


def test_a_tool_that_declares_a_capability_is_accepted() -> None:
    tool = _tool()
    assert tool.name == "graph_get"
    assert tool.capability == "graph:read"
    assert tool.public is False


def test_a_tool_with_neither_a_capability_nor_an_explicit_public_marker_is_refused() -> None:
    """The gate: no tool is implicitly public. Omission is not a decision."""
    with pytest.raises(McpToolDefinitionError):
        _tool(capability=None)


def test_an_explicitly_public_tool_is_accepted() -> None:
    tool = _tool(capability=None, public=True)
    assert tool.public is True
    assert tool.capability is None


def test_a_public_tool_that_also_names_a_capability_is_refused() -> None:
    """A tool is either public or capability-gated; saying both leaves the answer ambiguous."""
    with pytest.raises(McpToolDefinitionError):
        _tool(public=True)


def test_an_empty_capability_is_refused() -> None:
    with pytest.raises(McpToolDefinitionError):
        _tool(capability="")


@pytest.mark.parametrize(
    "name",
    ["", "Graph_Get", "graph-get", "graph get", "graph.get", "9graph", "graph:get", "a" * 65],
    ids=repr,
)
def test_a_tool_name_that_is_not_a_tool_name_is_refused(name: str) -> None:
    with pytest.raises(McpToolDefinitionError):
        _tool(name=name)


def test_a_tool_without_a_handler_is_refused() -> None:
    with pytest.raises(McpToolDefinitionError):
        _tool(handler=None)


def test_a_capability_gated_tool_without_an_authorization_target_is_refused() -> None:
    """The permission mapping needs both halves: what is acted on, and the action."""
    with pytest.raises(McpToolDefinitionError):
        _tool(resource_kind="")
    with pytest.raises(McpToolDefinitionError):
        _tool(action="")


def test_a_privileged_tool_is_marked_and_carries_its_capability() -> None:
    tool = _tool(name="graph_delete", capability="graph:delete", action="delete", privileged=True)
    assert tool.privileged is True
    assert tool.capability == "graph:delete"


def test_a_privileged_tool_cannot_be_public() -> None:
    """Privilege is an elevation on top of a capability, never a substitute for one."""
    with pytest.raises(McpToolDefinitionError):
        _tool(capability=None, public=True, privileged=True)


def test_a_sensitive_tool_is_marked() -> None:
    assert _tool(sensitive=True).sensitive is True


def test_the_registry_refuses_a_duplicate_name() -> None:
    registry = McpToolRegistry()
    registry.register(_tool())
    with pytest.raises(McpToolDefinitionError):
        registry.register(_tool(description="a second tool claiming the same name"))


def test_the_registry_returns_tools_deterministically() -> None:
    registry = McpToolRegistry()
    for name in ("graph_search", "graph_get", "graph_create"):
        registry.register(_tool(name=name))
    assert [tool.name for tool in registry.tools()] == [
        "graph_create",
        "graph_get",
        "graph_search",
    ]


def test_the_registry_reports_what_is_registered_and_what_each_tool_needs() -> None:
    """The inventory the programme's gate reads: a tool with no capability cannot appear here."""
    registry = McpToolRegistry()
    registry.register(_tool())
    registry.register(_tool(name="health_probe", capability=None, public=True))
    inventory = registry.inventory()
    assert inventory == (
        ("graph_get", "graph:read", False),
        ("health_probe", None, False),
    )
    assert all(
        capability is not None or name == "health_probe" for name, capability, _ in inventory
    )


def test_the_registry_refuses_an_unknown_tool_by_name() -> None:
    registry = McpToolRegistry()
    with pytest.raises(McpToolDefinitionError):
        registry.get("graph_get")


def test_a_registered_tool_is_retrieved_by_name() -> None:
    registry = McpToolRegistry()
    tool = _tool()
    registry.register(tool)
    assert registry.get("graph_get") is tool
