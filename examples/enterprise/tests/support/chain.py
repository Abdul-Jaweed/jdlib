"""The chain: the application's own composition, driven over both surfaces.

`build_collaborators` is what a deployment runs, `create_app` is what it serves, and the MCP server
is built from the *same* collaborators -- so a test that drives either surface is driving the
application, not a test double of it. The HTTP client goes through `httpx.ASGITransport` (the
repository's convention: no `TestClient`, which the suite's warning flags retire), and the tool
caller goes through the real `fastmcp` client over the real server.

Every engine is created inside the caller's event loop and disposed in it. An engine created in one
loop and closed in another reports itself as an unclosed connection, which the gate's `-W error`
turns into a failure of whichever test happens to run last.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import FastAPI

from examples.enterprise.app.main import Collaborators, build_collaborators, create_app
from examples.enterprise.app.mcp.server import McpSurface, build_example_mcp_server
from examples.enterprise.tests.support.lab import Caller

#: Where the application is mounted. The tenant plane lives under `/api`; the probes do not.
BASE_URL = "http://example.test"


@dataclass(slots=True)
class LiveApplication:
    """One composition, two surfaces, and the credentials the lab provisioned."""

    collaborators: Collaborators
    app: FastAPI
    client: httpx.AsyncClient

    async def http(
        self,
        caller: Caller | None,
        method: str,
        path: str,
        *,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """One request as `caller` -- or with no credential at all when `caller` is None."""
        sent = dict(headers or {})
        if caller is not None:
            sent["authorization"] = f"Bearer {caller.token}"
        return await self.client.request(method, path, json=json, headers=sent)

    async def tool(
        self, caller: Caller, tool: str, arguments: dict[str, object]
    ) -> Any:
        """One tool call as `caller`, through the real server and the real client.

        The server is built per call with that caller's request source: the boundary begins with a
        request, and which credential that request carries is the caller's identity -- a server that
        shared one credential across callers would make the isolation tests measure nothing.
        """
        from fastmcp import Client

        surface = McpSurface(
            resources=self.collaborators.resources,
            principal_provider=self.collaborators.principal_provider,
            chain=self.collaborators.chain,
            factory=self.collaborators.factory,
            enforcer=self.collaborators.enforcer,
            sink=self.collaborators.security_sink,
            graph_plane=self.collaborators.graph,
        )
        server = build_example_mcp_server(surface, request_source=caller.request)
        async with Client(server) as client:
            return await client.call_tool(tool, arguments)


@asynccontextmanager
async def application() -> AsyncIterator[LiveApplication]:
    """The application's collaborators and both surfaces, in *this* event loop."""
    collaborators = build_collaborators()
    app = create_app(collaborators)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE_URL, timeout=30.0
    )
    try:
        yield LiveApplication(collaborators=collaborators, app=app, client=client)
    finally:
        await client.aclose()
        await collaborators.aclose()


def http_call(
    caller: Caller | None,
    method: str,
    path: str,
    *,
    json: Any = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """One request through a freshly built application, in its own loop.

    For tests whose subject is the *answer* rather than the sequence: the composition is built,
    asked, and disposed inside one `asyncio.run`, so nothing outlives the call.
    """

    async def _body() -> httpx.Response:
        async with application() as live:
            return await live.http(caller, method, path, json=json, headers=headers)

    return asyncio.run(_body())
