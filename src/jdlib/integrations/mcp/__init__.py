"""The MCP surface as the library's own security boundary (directive §18–§28).

FastMCP is treated as another external application/API surface: it may not bypass the library, and
everything it exposes is declared, authorized, tenant-scoped, audited and observable. The pieces:

* `errors` — what this surface can refuse, in the library's taxonomy;
* `tools` — tools as declarations, with the registry that refuses an undeclared one.

The framework itself is an optional extra, imported where it is used rather than at import of this
package, so the library still imports without it.
"""

from __future__ import annotations

from jdlib.integrations.mcp.errors import McpError, McpToolDefinitionError
from jdlib.integrations.mcp.tools import McpTool, McpToolRegistry

__all__ = [
    "McpError",
    "McpTool",
    "McpToolDefinitionError",
    "McpToolRegistry",
]
