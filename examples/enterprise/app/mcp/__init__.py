"""The MCP surface: a second protocol over the same security chain.

`app/mcp/tools.py` declares the tools and `app/mcp/server.py` composes the server out of the
collaborators the HTTP path installs. The library owns the boundary, the invocation chain, the
registry's rules and the graph tools; this package owns the declarations, the wire shapes and the
runner a multi-tenant surface needs.
"""

from __future__ import annotations

from examples.enterprise.app.mcp.server import (
    McpSurface,
    TenantGraphRunner,
    build_example_mcp_server,
)
from examples.enterprise.app.mcp.tools import (
    READ_CAPABILITY,
    WRITE_CAPABILITY,
    resource_tools,
)

__all__ = [
    "READ_CAPABILITY",
    "WRITE_CAPABILITY",
    "McpSurface",
    "TenantGraphRunner",
    "build_example_mcp_server",
    "resource_tools",
]
