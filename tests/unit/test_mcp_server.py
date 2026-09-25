"""The server factory: what a client sees, and what it can make the library do (directive §18, §28).

§28 draws the chain `FastMCP → JDLib MCP Security → Cerbos → GraphRepository → Neo4j`, and this
slice is the first arrow: a FastMCP server whose tools *are* the registry's declarations, so the
surface cannot drift from the inventory the programme's gate reads.

Three properties are the point of the file.

**The extra stays optional.** `fastmcp` is a dependency of using the server, not of importing the
library. That is proved the only way it can be — in a subprocess where the module is blocked — and
the same subprocess runs a *control* case first, because a blocked import that proves nothing is
indistinguishable from a passing one. The subprocess also reports whether the extra is installed at
all: where it is absent, blocking it proves nothing and the test skips with that reason rather than
claiming a pass.

**The schema is the declaration.** §22 asks for typed tools, and the declarations carry
`additionalProperties: false` with no identity and no statement slot anywhere — the property the
graph-tools tests pin. A probe of fastmcp 4.0.10 showed that a `Tool` built with an explicit
`parameters` schema *advertises* that schema and does **not** enforce it: an undeclared argument
reached the handler. An advertised contract the library does not enforce is a lie told to every
client, so the invocation chain validates the arguments against the declaration before anything
else runs — and these tests drive that through the server, with the handler's call count as the
proof that a refusal refused.

**The transport supplies the request.** The chain begins with an authenticated request; over HTTP
that is fastmcp's own request object, which is where the default request source reads headers from.
Tests inject a source, because the in-memory client used here has no HTTP request at all.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from typing import Any

import pytest

from jdlib.integrations.mcp.tools import McpTool, McpToolRegistry
from jdlib.security.audit.events import AuditOutcome, SecurityEventType
from jdlib.tenancy.resolution import RequestInfo
from tests.support.graph_fakes import graph_context

TENANT_ID = uuid.UUID("77777777-7777-7777-7777-777777777777")

_BLOCKED_SCRIPT = '''
import importlib.util
import sys

present = importlib.util.find_spec("fastmcp") is not None
print("FASTMCP-PRESENT", present)

# The extra is "not installed", in the only way this process can be made to believe it.
sys.modules["fastmcp"] = None
try:
    import fastmcp  # noqa: F401
    print("CONTROL-IMPORT-SUCCEEDED")
except ImportError:
    print("CONTROL-BLOCKED")

import jdlib.integrations.mcp.server as server

print("IMPORTED-WITHOUT-EXTRA")

from jdlib.integrations.mcp.tools import McpToolRegistry

try:
    server.build_mcp_server(
        boundary=None,
        registry=McpToolRegistry(),
        enforcer=None,
    )
    print("FACTORY-SUCCEEDED")
except Exception as exc:  # noqa: BLE001 - the test asserts on the class it names
    print("FACTORY-REFUSED", type(exc).__name__, "jdlib[mcp]" in str(exc))
'''


def _run_blocked() -> str:
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    proc = subprocess.run(
        [sys.executable, "-c", _BLOCKED_SCRIPT],
        capture_output=True,
        text=True,
        cwd=repo,
        env={**os.environ, "PYTHONPATH": repo},
    )
    assert proc.returncode == 0, proc.stderr[-800:]
    return proc.stdout


def test_the_core_import_does_not_need_the_extra() -> None:
    out = _run_blocked()
    if "FASTMCP-PRESENT True" not in out:
        pytest.skip("the extra is not installed, so blocking it proves nothing")
    assert "CONTROL-BLOCKED" in out, "the blocker did not block: the control case must fail"
    assert "IMPORTED-WITHOUT-EXTRA" in out


def test_the_factory_refuses_with_a_named_error_when_the_extra_is_absent() -> None:
    out = _run_blocked()
    if "FASTMCP-PRESENT True" not in out:
        pytest.skip("the extra is not installed, so blocking it proves nothing")
    assert "CONTROL-BLOCKED" in out
    assert "FACTORY-REFUSED McpServerUnavailableError True" in out


def _fastmcp() -> Any:
    return pytest.importorskip("fastmcp", reason="the mcp extra is not installed")


def _schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"node_id": {"type": "string"}},
        "required": ["node_id"],
        "additionalProperties": False,
    }


class _Handler:
    def __init__(self) -> None:
        self.calls = 0
        self.seen: list[dict[str, Any]] = []

    async def __call__(self, **arguments: Any) -> Any:
        self.calls += 1
        self.seen.append(arguments)
        return {"node_id": arguments.get("node_id")}


class _Boundary:
    def __init__(self) -> None:
        self.seen: list[RequestInfo] = []

    async def establish(self, *, request: RequestInfo) -> Any:
        self.seen.append(request)
        return graph_context(tenant_id=TENANT_ID)


class _Enforcer:
    def __init__(self, *, denies: bool = False) -> None:
        self.denies = denies
        self.asked: list[str] = []

    async def require(self, permission: str, target: Any, *, session: Any) -> Any:
        self.asked.append(permission)
        if self.denies:
            from jdlib.errors import PermissionDenied

            raise PermissionDenied("denied by the test double")
        return None


class _Emitter:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def __call__(self, event: Any) -> None:
        self.events.append(event)

    def named(self, event_type: SecurityEventType) -> list[Any]:
        return [event for event in self.events if event.event_type is event_type]


def _request() -> RequestInfo:
    return RequestInfo(
        headers={"authorization": "Bearer fixture-marker"},
        query={},
        path="mcp://tool/graph_get",
        host="mcp",
    )


def _registry(handler: _Handler, *, declared: bool = True) -> McpToolRegistry:
    registry = McpToolRegistry()
    registry.register(
        McpTool(
            name="graph_get",
            description="Read one node.",
            handler=handler,
            capability="graph:read",
            resource_kind="graph_node",
            action="read",
            input_schema=_schema() if declared else {},
        )
    )
    return registry


def _server(
    *,
    handler: _Handler | None = None,
    registry: McpToolRegistry | None = None,
    enforcer: _Enforcer | None = None,
    emitter: _Emitter | None = None,
    boundary: _Boundary | None = None,
) -> Any:
    from jdlib.integrations.mcp.server import build_mcp_server

    _fastmcp()
    return build_mcp_server(
        boundary=boundary or _Boundary(),  # type: ignore[arg-type]
        registry=registry or _registry(handler or _Handler()),
        enforcer=enforcer or _Enforcer(),
        emitter=emitter,
        request_source=_request,
    )


async def test_the_server_registers_exactly_the_declared_tools() -> None:
    server = _server()
    listed = await server.list_tools()
    assert [tool.name for tool in listed] == ["graph_get"]


async def test_the_registered_schema_is_the_declaration() -> None:
    server = _server()
    (tool,) = await server.list_tools()
    assert tool.parameters == _schema()


async def test_a_registry_with_no_tools_yields_a_server_with_no_tools() -> None:
    """The surface is the inventory: no hard-coded tools, no implicit public one."""
    server = _server(registry=McpToolRegistry())
    assert await server.list_tools() == []


async def test_an_undeclared_argument_is_refused_before_the_handler_runs() -> None:
    """fastmcp 4.0.10 advertises `additionalProperties: false` and does not enforce it."""
    _fastmcp()
    from fastmcp.exceptions import ToolError

    handler = _Handler()
    emitter = _Emitter()
    server = _server(handler=handler, emitter=emitter)
    _fastmcp()
    from fastmcp import Client

    async with Client(server) as client:
        with pytest.raises(ToolError):
            await client.call_tool("graph_get", {"node_id": "n1", "tenant_id": str(TENANT_ID)})
    assert handler.calls == 0
    errors = emitter.named(SecurityEventType.MCP_ERROR)
    assert [event.metadata.get("error") for event in errors] == ["McpArgumentsRefusedError"]


async def test_a_missing_required_argument_is_refused_before_the_handler_runs() -> None:
    _fastmcp()
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    handler = _Handler()
    server = _server(handler=handler)
    async with Client(server) as client:
        with pytest.raises(ToolError):
            await client.call_tool("graph_get", {})
    assert handler.calls == 0


async def test_a_call_through_the_server_runs_the_chain() -> None:
    _fastmcp()
    from fastmcp import Client

    handler = _Handler()
    emitter = _Emitter()
    boundary = _Boundary()
    enforcer = _Enforcer()
    server = _server(handler=handler, emitter=emitter, boundary=boundary, enforcer=enforcer)
    async with Client(server) as client:
        result = await client.call_tool("graph_get", {"node_id": "n1"})
    assert handler.seen == [{"node_id": "n1"}]
    assert result.data == {"node_id": "n1"}
    assert enforcer.asked == ["graph:read"]
    assert boundary.seen and boundary.seen[0].headers["authorization"].startswith("Bearer")
    invoked = emitter.named(SecurityEventType.MCP_TOOL_INVOKED)
    assert len(invoked) == 1
    assert invoked[0].tenant_id == TENANT_ID
    assert invoked[0].principal_id is not None
    assert invoked[0].outcome is AuditOutcome.SUCCESS


async def test_a_denied_call_through_the_server_never_runs_the_handler() -> None:
    _fastmcp()
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    handler = _Handler()
    emitter = _Emitter()
    server = _server(handler=handler, emitter=emitter, enforcer=_Enforcer(denies=True))
    async with Client(server) as client:
        with pytest.raises(ToolError):
            await client.call_tool("graph_get", {"node_id": "n1"})
    assert handler.calls == 0
    denied = emitter.named(SecurityEventType.AUTHZ_DENY)
    assert len(denied) == 1
    assert denied[0].action == "mcp.authorization.denied"


async def test_a_resource_is_registered_and_read_through_the_server() -> None:
    _fastmcp()
    from fastmcp import Client

    from jdlib.integrations.mcp.resources import McpResource
    from jdlib.integrations.mcp.server import build_mcp_server

    async def reader() -> dict[str, Any]:
        return {"tenant_id": str(TENANT_ID), "state": "ok"}

    resource = McpResource(
        uri="jdlib://probe",
        name="probe",
        description="A probe resource.",
        handler=reader,
        capability="graph:read",
    )
    emitter = _Emitter()
    server = build_mcp_server(
        boundary=_Boundary(),  # type: ignore[arg-type]
        registry=McpToolRegistry(),
        enforcer=_Enforcer(),
        emitter=emitter,
        resources=[resource],
        request_source=_request,
    )
    listed = await server.list_resources()
    assert [str(entry.uri) for entry in listed] == ["jdlib://probe"]
    async with Client(server) as client:
        content = await client.read_resource("jdlib://probe")
    text = getattr(content[0], "text", None)
    assert json.loads(str(text)) == {"tenant_id": str(TENANT_ID), "state": "ok"}
    reads = emitter.named(SecurityEventType.MCP_RESOURCE_READ)
    assert len(reads) == 1
