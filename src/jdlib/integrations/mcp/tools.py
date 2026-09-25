"""Tools as declarations, not as functions someone remembered to protect (directive §20, §22).

The directive's rule is that *no tool should be implicitly public unless explicitly designed as
public*, and that every tool has an authorization requirement. A rule like that, enforced by
review, is enforced until someone is in a hurry. So it is enforced here, in the type: a tool
either names the capability it requires, or it says `public=True` in so many words. Omitting the
question is not an answer to it, and the omission cannot be constructed.

The same shape carries the rest of what a tool must declare — the resource kind and action its
permission maps to, whether it is privileged (an elevation on top of a capability, never a
substitute for one) and whether it is sensitive — so the registry's inventory is a complete
statement of what the surface exposes and what each exposure costs.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from jdlib.integrations.mcp.errors import McpToolDefinitionError

#: MCP tool names are the names a client types: lower case, no punctuation, no spaces. A name
#: that a client cannot address is a tool that cannot be called, so it is refused here.
_TOOL_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


@dataclass(frozen=True, slots=True)
class McpTool:
    """One tool: its name, what it needs, and what it does.

    ``capability`` is the library's own capability string — the same vocabulary the HTTP routes
    require — and it is what the PEP is asked about, alongside ``resource_kind`` and ``action``.
    ``public`` is the explicit marker for a tool that genuinely needs no capability, and the only
    way to have none.
    """

    name: str
    description: str
    handler: Callable[..., Awaitable[Any]]
    capability: str | None = None
    public: bool = False
    resource_kind: str = ""
    action: str = ""
    privileged: bool = False
    sensitive: bool = False
    input_schema: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _TOOL_NAME_PATTERN.fullmatch(self.name):
            raise McpToolDefinitionError(
                f"{self.name!r} is not a tool name: lower-case letters, digits and underscores, "
                "starting with a letter"
            )
        if not self.description.strip():
            raise McpToolDefinitionError(
                f"tool {self.name!r} needs a description: a tool a client cannot explain is a "
                "tool it cannot choose safely"
            )
        if not callable(self.handler):
            raise McpToolDefinitionError(f"tool {self.name!r} needs a callable handler")
        if self.public and self.capability is not None:
            raise McpToolDefinitionError(
                f"tool {self.name!r} is marked public and names a capability: a tool is one or "
                "the other, and saying both leaves the answer ambiguous"
            )
        if not self.public and not self.capability:
            raise McpToolDefinitionError(
                f"tool {self.name!r} declares no capability: name the capability it requires, or "
                "mark it public=True deliberately — no tool is implicitly public"
            )
        if self.privileged and self.public:
            raise McpToolDefinitionError(
                f"tool {self.name!r} is privileged and public: privilege is an elevation on top "
                "of a capability, never a substitute for one"
            )
        if not self.public and not (self.resource_kind and self.action):
            raise McpToolDefinitionError(
                f"tool {self.name!r} needs both halves of its authorization target: the resource "
                "kind it acts on and the action it takes"
            )


class McpToolRegistry:
    """What the surface exposes, as a value an operator can read and a test can check."""

    def __init__(self) -> None:
        self._tools: dict[str, McpTool] = {}

    def register(self, tool: McpTool) -> McpTool:
        """Add a tool. A name is taken once: a second tool claiming it is a definition error."""
        if tool.name in self._tools:
            raise McpToolDefinitionError(f"a tool named {tool.name!r} is already registered")
        self._tools[tool.name] = tool
        return tool

    def get(self, name: str) -> McpTool:
        """The tool with this name, or a refusal naming it."""
        tool = self._tools.get(name)
        if tool is None:
            raise McpToolDefinitionError(f"no tool named {name!r} is registered")
        return tool

    def tools(self) -> tuple[McpTool, ...]:
        """Every tool, in name order, so the surface is described deterministically."""
        return tuple(self._tools[name] for name in sorted(self._tools))

    def inventory(self) -> tuple[tuple[str, str | None, bool], ...]:
        """``(name, capability, privileged)`` per tool — the whole surface in one value.

        A tool with no capability appears here with ``None`` only when it was marked public
        deliberately, so a test over this tuple is a test over every exposure the surface makes.
        """
        return tuple((tool.name, tool.capability, tool.privileged) for tool in self.tools())
