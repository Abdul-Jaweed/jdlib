"""The server factory: the registry's declarations, served over MCP (directive §18, §28).

§28 draws the chain `FastMCP → JDLib MCP Security → Cerbos → GraphRepository → Neo4j`. This module
is the first arrow and nothing else: it does not authenticate, authorize, resolve a tenant, audit
or reach a database — it hands the library's own boundary, registry and enforcer to the same
`McpInvoker` the rest of the surface uses, and registers one FastMCP tool per declaration.

Two consequences worth stating, because they are the reason the module is this thin:

* **The surface is the inventory.** Tools come from `registry.tools()`, so a tool cannot exist on
  the wire without existing in the inventory the programme's gate reads. There is no list here to
  drift, and a registry with nothing in it yields a server with nothing on it.
* **fastmcp stays optional.** It is imported inside the factory, not at module import, so a
  deployment that never builds a server never installs it. Where it is missing the factory raises
  `McpServerUnavailableError` naming the extra, and a subprocess test proves the import path does
  not need it — with a control case, because a blocked import that proves nothing looks exactly
  like a passing one.

The request source is the third seam. The chain begins with an authenticated request, and over
HTTP that is fastmcp's own request object; the default source reads it. It is injectable because
tests and in-process callers have no HTTP request at all, and pretending otherwise would mean
either a fake transport in every test or an unauthenticated path in production.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from jdlib.integrations.mcp.errors import McpServerUnavailableError
from jdlib.integrations.mcp.invocation import McpInvoker
from jdlib.integrations.mcp.resources import McpResource
from jdlib.integrations.mcp.tools import McpTool, McpToolRegistry
from jdlib.tenancy.resolution import RequestInfo

#: The extra a deployment installs to serve MCP. Named in the refusal so the fix is in the message.
MCP_EXTRA = "jdlib[mcp]"


def _load_fastmcp() -> Any:
    """Import fastmcp at the point of use, and say what to install when it is absent."""
    try:
        import fastmcp
    except ImportError as exc:  # pragma: no cover - exercised in a subprocess, not in-process
        raise McpServerUnavailableError(
            f"serving MCP needs fastmcp, which is an optional extra: install {MCP_EXTRA}"
        ) from exc
    return fastmcp


def request_from_http() -> RequestInfo:
    """The request the chain authenticates, read from the HTTP request fastmcp is serving.

    Header names are lower-cased because the library's authenticator reads them by their
    canonical names, and a transport is not the place to discover that two spellings exist.
    """
    from fastmcp.server.dependencies import get_http_request

    request = get_http_request()
    return RequestInfo(
        headers={name.lower(): value for name, value in request.headers.items()},
        query=dict(request.query_params),
        path=request.url.path,
        host=request.url.hostname or "",
    )


def build_mcp_server(
    *,
    boundary: Any,
    registry: McpToolRegistry,
    enforcer: Any,
    uow_factory: Callable[[], Any] | None = None,
    emitter: Any = None,
    tracer: Any = None,
    resources: Sequence[McpResource] = (),
    gate: Any = None,
    timeout: float | None = None,
    shutdown: Any = None,
    name: str = "jdlib",
    request_source: Callable[[], RequestInfo] | None = None,
) -> Any:
    """Compose a FastMCP server whose tools and resources are the given declarations."""
    fastmcp = _load_fastmcp()
    source = request_source or request_from_http
    declarations = tuple(resources)
    invoker = McpInvoker(
        boundary=boundary,
        registry=registry,
        enforcer=enforcer,
        uow_factory=uow_factory,
        emitter=emitter,
        tracer=tracer,
        gate=gate,
        timeout=timeout,
        shutdown=shutdown,
        resources={resource.uri: resource for resource in declarations},
    )
    server = fastmcp.FastMCP(name=name)
    for tool in registry.tools():
        server.add_tool(_tool_for(tool, invoker, source))
    for resource in declarations:
        _register_resource(server, resource, invoker, source)
    return server


def _tool_for(
    tool: McpTool, invoker: McpInvoker, source: Callable[[], RequestInfo]
) -> Any:
    """One FastMCP tool per declaration, carrying the declaration's own schema.

    The schema is set from the declaration rather than derived from the wrapper's signature: a
    signature of `**arguments` would advertise a free-form object and lose exactly the property
    the declarations exist to state. The library enforces the schema it advertises (see
    `invocation._refuse_undeclared`) because fastmcp 4.0.10 does not.
    """
    from fastmcp.tools import FunctionTool

    async def call(**arguments: Any) -> Any:
        return await invoker.invoke(tool_name=tool.name, arguments=arguments, request=source())

    return FunctionTool(
        name=tool.name,
        description=tool.description,
        parameters=dict(tool.input_schema),
        fn=call,
    )


def _register_resource(
    server: Any,
    resource: McpResource,
    invoker: McpInvoker,
    source: Callable[[], RequestInfo],
) -> None:
    """Register one read-only resource, served through the same chain as a tool call.

    Registered through the server's own decorator rather than by constructing the resource
    class: the decorator takes the declaration's plain `str` URI and owns the conversion the
    transport expects, so the declaration keeps strings — a URI is data, not a type.
    """

    async def read() -> Any:
        return await invoker.invoke_resource(uri=resource.uri, request=source())

    server.resource(resource.uri, name=resource.name, mime_type="application/json")(read)
