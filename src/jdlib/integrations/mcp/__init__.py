"""The MCP surface as the library's own security boundary (directive §18–§28).

FastMCP is treated as another external application/API surface: it may not bypass the library, and
everything it exposes is declared, authorized, tenant-scoped, audited and observable. The pieces:

* `errors` — what this surface can refuse, in the library's taxonomy;
* `tools` — tools as declarations, with the registry that refuses an undeclared one;
* `boundary` — the HTTP edge's own authentication and tenant resolution, run for this surface;
* `invocation` — boundary → decision → handler → record, with the denial proven non-executing;
* `graph_tools` — the graph's operations, declared, with nowhere to put an identity or a statement;
* `resources` — read-only bodies whose rule is what they may never say.

The framework itself is an optional extra, imported where it is used rather than at import of this
package, so the library still imports without it.
"""

from __future__ import annotations

from jdlib.integrations.mcp.boundary import McpSecurityBoundary
from jdlib.integrations.mcp.errors import (
    McpError,
    McpToolDefinitionError,
    McpToolExecutionError,
)
from jdlib.integrations.mcp.graph_tools import graph_tools
from jdlib.integrations.mcp.invocation import McpInvoker
from jdlib.integrations.mcp.resources import (
    McpResource,
    graph_schema_resource,
    health_resource,
    tenant_resource,
)
from jdlib.integrations.mcp.tools import McpTool, McpToolRegistry

__all__ = [
    "McpError",
    "McpInvoker",
    "McpSecurityBoundary",
    "McpTool",
    "McpToolDefinitionError",
    "McpToolExecutionError",
    "McpResource",
    "McpToolRegistry",
    "graph_schema_resource",
    "graph_tools",
    "health_resource",
    "tenant_resource",
]
