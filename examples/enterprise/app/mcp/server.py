"""The MCP surface: the same chain, a second protocol.

The directive's chain — MCP → security boundary → `SecurityContext` → authentication → tenant
resolution → authorization → service — is not re-implemented here. Every collaborator below is the
object the HTTP path already installs, handed to the library's own `McpSecurityBoundary` and
`build_mcp_server`, which is what makes "the same security model on both surfaces" a fact rather
than a claim: a second authenticator, a second resolver chain or a second enforcer would be a second
place for a decision to drift, and the tests assert the *identity* of the collaborators rather than
their shape.

Two things this surface adds that HTTP did not need:

* a **runner** for the graph tools. `GraphRepository` takes a runner, and a graph client *is* a
  tenant binding, so a surface that serves every tenant cannot hold one client: `TenantGraphRunner`
  opens (or reuses) the calling tenant's client per statement, and the tenant still comes from the
  context.
* an **emitter** for a synchronous boundary over an asynchronous sink. The library ships
  `AsyncSinkEmitter` for exactly this, and the example's audit sink is the same one the HTTP path
  writes to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from examples.enterprise.app.graph import VOCABULARY, GraphPlane
from examples.enterprise.app.mcp.tools import resource_tools
from examples.enterprise.app.services.resources import ResourceService
from jdlib.context import ContextFactory
from jdlib.graph.repository import GraphRepository
from jdlib.integrations.mcp.boundary import McpSecurityBoundary
from jdlib.integrations.mcp.graph_tools import graph_tools
from jdlib.integrations.mcp.server import build_mcp_server
from jdlib.integrations.mcp.tools import McpToolRegistry
from jdlib.security.audit.emitter import AsyncSinkEmitter
from jdlib.security.audit.emitters import SecurityEventSink
from jdlib.tenancy.middleware import PrincipalProvider
from jdlib.tenancy.resolution import ResolverChain

__all__ = ["McpSurface", "TenantGraphRunner", "build_example_mcp_server"]


class TenantGraphRunner:
    """The runner the graph tools get: one repository, the calling tenant's client per statement.

    The repository is built once — its vocabulary and its statements are the same for every tenant —
    while the client is opened for the tenant the call's context names. Handing the tools a client
    instead would either serve the first tenant's binding to the second or refuse every call after
    it, and both are wrong in ways only a live database shows.
    """

    def __init__(self, plane: GraphPlane) -> None:
        self._plane = plane

    async def run(self, *, query: Any, context: Any) -> Any:
        client = await self._plane.client_for(context)
        return await client.run(query=query, context=context)


@dataclass(frozen=True, slots=True)
class McpSurface:
    """The collaborators this surface reuses — the same objects the HTTP path installs.

    A frozen dataclass rather than a parameter list: the point is that these are *the* objects
    `create_app` built, and a signature that could be handed different ones invites a second chain
    to grow quietly.
    """

    resources: ResourceService
    principal_provider: PrincipalProvider
    chain: ResolverChain
    factory: ContextFactory
    enforcer: Any
    sink: SecurityEventSink
    graph_plane: GraphPlane | None = None


def build_example_mcp_server(
    surface: McpSurface, *, tracer: Any = None, request_source: Any = None
) -> Any:
    """The MCP server: the registry, the boundary, and the enforcer, wired by the library.

    The registry is the surface: no tool exists that is not declared here, and every declaration
    carries the capability its authorization is asked against. The graph tools join it only when a
    graph is configured, because a tool that cannot work is worse than a tool that is absent.

    `request_source` is forwarded to the library's factory, which takes it because the boundary
    begins with a *request*: over HTTP that is fastmcp's own, and a client driven in memory has none
    to read headers from.
    """
    registry = McpToolRegistry()
    for tool in resource_tools(surface.resources):
        registry.register(tool)
    if surface.graph_plane is not None:
        runner = TenantGraphRunner(surface.graph_plane)
        repository = GraphRepository(client=runner, vocabulary=VOCABULARY)
        for tool in graph_tools(repository):
            registry.register(tool)

    boundary = McpSecurityBoundary(
        principal_provider=surface.principal_provider,
        chain=surface.chain,
        factory=surface.factory,
        tracer=tracer,
        emitter=AsyncSinkEmitter(surface.sink),
    )
    return build_mcp_server(
        boundary=boundary,
        registry=registry,
        enforcer=surface.enforcer,
        emitter=AsyncSinkEmitter(surface.sink),
        tracer=tracer,
        request_source=request_source,
    )
