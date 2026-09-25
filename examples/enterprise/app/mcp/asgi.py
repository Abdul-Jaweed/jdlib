"""The MCP server as its own entry point.

    python -m examples.enterprise.app.mcp.asgi

The collaborators are the HTTP app's own (`build_collaborators`), so the two surfaces are one
deployment with two protocols rather than two deployments that happen to share a database.

Nothing is built at import: a module that needs a complete environment to be *imported* cannot be
imported by a tool that only wants to read it — a docs check, an inspector, a test collecting the
package. `build_server` is the entry point, and `main` is what the command above runs.
"""

from __future__ import annotations

from typing import Any

from examples.enterprise.app.main import Collaborators, build_collaborators
from examples.enterprise.app.mcp.server import McpSurface, build_example_mcp_server


def build_mcp_surface(collaborators: Collaborators) -> McpSurface:
    """The collaborators, as the MCP surface needs them."""
    return McpSurface(
        resources=collaborators.resources,
        principal_provider=collaborators.principal_provider,
        chain=collaborators.chain,
        factory=collaborators.factory,
        enforcer=collaborators.enforcer,
        sink=collaborators.security_sink,
        graph_plane=collaborators.graph,
    )


def build_server() -> Any:
    """The server, from the environment. Raises when the environment is incomplete."""
    return build_example_mcp_server(build_mcp_surface(build_collaborators()))


def main() -> None:
    """Serve MCP over streamable HTTP, on the transport fastmcp serves by default."""
    build_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
