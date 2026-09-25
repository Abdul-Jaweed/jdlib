"""Attacks on the MCP surface, through the paths a caller actually reaches (directive §19-§25).

The unit tests around this file prove the surface works. This one tries to make it do something
it should not, and the standard is the one the graph phase set: an attack must go through the
enforcement path, a refusal the test caused itself is no evidence, and **a refusal is proven by
non-execution** — the handler's call count, not the exception's type. A refusal that still ran
the work passes every assertion on the exception and fails the only one that matters.

The attacks:

* **The wire, not the declaration.** The schemas the seven graph tools *advertise* are swept for
  anywhere an identity or a statement could be put — the same property the declarations are
  tested for, checked through the transport a client actually reads.
* **An identity injected into every tool.** Each declaration is called with its required
  arguments plus a `tenant_id`, and the repository behind them must never be touched.
* **A resource URI nobody registered.** `self._resources.get(uri)` answers `None` for an unknown
  URI, and the code after it reads an attribute — a caller-supplied string reaching an attribute
  access is the shape this whole phase exists to refuse.
* **A forged tool name.** The registry's pattern is anchored; a name with a trailing space, a
  newline or a different case is a different name, and must not reach the tool it resembles.
* **A value the caller supplied, in the refusal.** An argument carrying a DSN-shaped string must
  appear in neither the exception nor the audit trail — the trail records the kind of failure,
  never the caller's text.
* **Context bleed.** Two calls with different tenants must not see each other's context, and the
  ambient context must be unset once a call returns.

One attack is deliberately *absent* from the non-execution table: a deadline that fires has, by
definition, started the work. "Nothing ran" is the wrong claim for a timeout — which is exactly
why `McpTimeoutError` says the operation may or may not have completed instead of claiming
either.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from jdlib.errors import AuthenticationError
from jdlib.integrations.mcp.errors import (
    McpArgumentsRefusedError,
    McpResourceDefinitionError,
    McpTimeoutError,
    McpToolDefinitionError,
)
from jdlib.integrations.mcp.graph_tools import graph_tools
from jdlib.integrations.mcp.invocation import McpInvoker
from jdlib.integrations.mcp.resources import McpResource
from jdlib.integrations.mcp.tools import McpTool, McpToolRegistry
from jdlib.reliability.concurrency import ConcurrencyGate
from jdlib.reliability.lifecycle import ShutdownCoordinator
from jdlib.security.audit.events import SecurityEventType
from jdlib.security.context import current_security_context
from jdlib.tenancy.resolution import RequestInfo
from tests.support.graph_fakes import graph_context

TENANT_ID = uuid.UUID("88888888-8888-8888-8888-888888888888")

#: Substrings that would mean a schema has somewhere to put a caller's identity.
_IDENTITY_HINTS = (
    "tenant",
    "user",
    "principal",
    "role",
    "scope",
    "subject",
    "actor",
    "owner",
    "account",
    "identity",
    "sub",
)

#: Substrings that would mean a schema has somewhere to put a statement.
_STATEMENT_HINTS = (
    "query",
    "cypher",
    "statement",
    "sql",
    "raw",
    "command",
    "expression",
    "script",
)


class _NeverReached:
    """A repository double that records any attribute call — so "never reached" is a fact.

    The refusal tests assert `calls == []`: a handler that ran and failed to find the attribute
    would leave a mark here even if its exception were swallowed.
    """

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        async def _call(*args: Any, **kwargs: Any) -> Any:
            self.calls.append(name)
            return None

        return _call


class _Boundary:
    def __init__(self, *, tenant: uuid.UUID = TENANT_ID) -> None:
        self.tenant = tenant
        self.seen: list[RequestInfo] = []

    async def establish(self, *, request: RequestInfo) -> Any:
        self.seen.append(request)
        return graph_context(tenant_id=self.tenant)


class _AlternatingBoundary:
    """A boundary whose tenant changes per call, to prove one call cannot see another's."""

    def __init__(self) -> None:
        self.n = 0

    async def establish(self, *, request: RequestInfo) -> Any:
        self.n += 1
        return graph_context(tenant_id=uuid.UUID(int=self.n))


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


class _Handler:
    def __init__(self, *, delay: float = 0.0) -> None:
        self.calls = 0
        self.delay = delay

    async def __call__(self, **arguments: Any) -> Any:
        self.calls += 1
        if self.delay:
            import asyncio

            await asyncio.sleep(self.delay)
        return {"ok": True}


def _request() -> RequestInfo:
    return RequestInfo(
        headers={"authorization": "Bearer fixture-marker"},
        query={},
        path="mcp://tool/graph_get",
        host="mcp",
    )


def _node_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"node_id": {"type": "string"}},
        "required": ["node_id"],
        "additionalProperties": False,
    }


def _tool(handler: Any, *, name: str = "graph_get") -> McpTool:
    return McpTool(
        name=name,
        description="Read one node.",
        handler=handler,
        capability="graph:read",
        resource_kind="graph_node",
        action="read",
        input_schema=_node_schema(),
    )


def _invoker(
    *,
    handler: Any = None,
    registry: McpToolRegistry | None = None,
    boundary: Any = None,
    enforcer: Any = None,
    emitter: _Emitter | None = None,
    resources: Any = None,
    gate: ConcurrencyGate | None = None,
    shutdown: ShutdownCoordinator | None = None,
    timeout: float | None = None,
) -> tuple[McpInvoker, _Emitter]:
    the_emitter = emitter if emitter is not None else _Emitter()
    if registry is None:
        registry = McpToolRegistry()
        registry.register(_tool(handler if handler is not None else _Handler()))
    invoker = McpInvoker(
        boundary=boundary if boundary is not None else _Boundary(),
        registry=registry,
        enforcer=enforcer if enforcer is not None else _Enforcer(),
        emitter=the_emitter,
        resources=resources,
        gate=gate,
        shutdown=shutdown,
        timeout=timeout,
    )
    return invoker, the_emitter


def _server(*, registry: McpToolRegistry, resources: tuple[McpResource, ...] = ()) -> Any:
    pytest.importorskip("fastmcp", reason="the mcp extra is not installed")
    from jdlib.integrations.mcp.server import build_mcp_server

    return build_mcp_server(
        boundary=_Boundary(),  # type: ignore[arg-type]
        registry=registry,
        enforcer=_Enforcer(),
        request_source=_request,
        resources=resources,
    )


def _graph_registry(repository: _NeverReached) -> McpToolRegistry:
    registry = McpToolRegistry()
    for tool in graph_tools(repository):  # type: ignore[arg-type]
        registry.register(tool)
    return registry


def _required_arguments(tool: McpTool) -> dict[str, Any]:
    required = tool.input_schema.get("required") or ()
    return {str(name): "placeholder" for name in required}


async def test_no_advertised_schema_has_anywhere_for_an_identity_or_a_statement() -> None:
    """The wire, not the declaration: this is the schema a client reads and a model fills in."""
    pytest.importorskip("fastmcp", reason="the mcp extra is not installed")
    from fastmcp import Client

    repository = _NeverReached()
    registry = _graph_registry(repository)
    server = _server(registry=registry)
    async with Client(server) as client:
        advertised = await client.list_tools()
    assert len(advertised) == 7
    for tool in advertised:
        schema = tool.input_schema
        properties = schema.get("properties") or {}
        assert schema.get("additionalProperties") is False, tool.name
        for name in properties:
            lowered = str(name).lower()
            assert not any(hint in lowered for hint in _IDENTITY_HINTS), (tool.name, name)
            assert not any(hint in lowered for hint in _STATEMENT_HINTS), (tool.name, name)
        for name in schema.get("required") or ():
            lowered = str(name).lower()
            assert not any(hint in lowered for hint in _IDENTITY_HINTS), (tool.name, name)


async def test_an_identity_injected_into_any_tool_never_reaches_the_repository() -> None:
    """Every declaration, not one: an injection slot in any single tool is a hole."""
    pytest.importorskip("fastmcp", reason="the mcp extra is not installed")
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    repository = _NeverReached()
    registry = _graph_registry(repository)
    server = _server(registry=registry)
    async with Client(server) as client:
        for tool in registry.tools():
            arguments = {**_required_arguments(tool), "tenant_id": str(TENANT_ID)}
            with pytest.raises(ToolError):
                await client.call_tool(tool.name, arguments)
    assert repository.calls == []


async def test_an_unregistered_resource_uri_is_refused_by_name() -> None:
    """`get(uri)` answers None for an unknown URI; the next line reads an attribute."""
    invoker, _ = _invoker(resources={"jdlib://tenant": object()})
    with pytest.raises(McpResourceDefinitionError):
        await invoker.invoke_resource(uri="jdlib://nope", request=_request())


async def test_a_denied_resource_read_runs_nothing_and_returns_nothing() -> None:
    handler = _Handler()
    resource = McpResource(
        uri="jdlib://probe",
        name="probe",
        description="A probe resource.",
        handler=handler,
        capability="graph:read",
    )
    enforcer = _Enforcer(denies=True)
    invoker, _ = _invoker(resources={resource.uri: resource}, enforcer=enforcer)
    from jdlib.errors import PermissionDenied

    with pytest.raises(PermissionDenied):
        await invoker.invoke_resource(uri=resource.uri, request=_request())
    assert enforcer.asked == ["graph:read"]
    assert handler.calls == 0


async def test_a_forged_tool_name_never_reaches_the_tool_it_resembles() -> None:
    pytest.importorskip("fastmcp", reason="the mcp extra is not installed")
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    handler = _Handler()
    registry = McpToolRegistry()
    registry.register(_tool(handler))
    server = _server(registry=registry)
    forged = ["graph_get ", " graph_get", "graph_get\n", "GRAPH_GET", "graph-get", "graph_get;"]
    async with Client(server) as client:
        for name in forged:
            with pytest.raises(ToolError):
                await client.call_tool(name, {"node_id": "n1"})
    assert handler.calls == 0


def test_a_forged_tool_name_cannot_be_registered_either() -> None:
    for name in ("graph_get ", " graph_get", "graph_get\n", "GRAPH_GET", "graph-get", "graph_get;"):
        with pytest.raises(McpToolDefinitionError):
            _tool(_Handler(), name=name)


async def test_a_value_the_caller_supplied_never_appears_in_the_refusal() -> None:
    """The trail records the kind of failure, never the caller's text."""
    planted = "dsn=postgresql://user:pw@host/db"
    invoker, emitter = _invoker(handler=_Handler())
    with pytest.raises(McpArgumentsRefusedError) as caught:
        await invoker.invoke(
            tool_name="graph_get",
            arguments={"node_id": "n1", "extra": planted},
            request=_request(),
        )
    assert planted not in str(caught.value)
    errors = emitter.named(SecurityEventType.MCP_ERROR)
    assert len(errors) == 1
    assert planted not in repr(errors[0])
    assert planted not in repr(errors[0].metadata)


async def test_no_context_bleeds_between_calls_or_past_them() -> None:
    seen: list[str] = []

    async def reader(**arguments: Any) -> Any:
        seen.append(str(current_security_context().require_tenant().tenant_id))
        return {"ok": True}

    boundary = _AlternatingBoundary()
    invoker, _ = _invoker(handler=reader, boundary=boundary)
    for _ in range(2):
        await invoker.invoke(tool_name="graph_get", arguments={"node_id": "n1"}, request=_request())
    assert seen == [str(uuid.UUID(int=1)), str(uuid.UUID(int=2))]
    with pytest.raises(AuthenticationError):
        current_security_context()


async def test_every_refusal_path_refuses_by_not_running_the_work() -> None:
    """The kill-shot table: each refusal is proven by the handler's call count."""
    from jdlib.errors import PermissionDenied
    from jdlib.reliability.concurrency import ConcurrencyLimitError
    from jdlib.reliability.lifecycle import ShutdownInProgressError

    async def _undeclared() -> None:
        handler = _Handler()
        invoker, _ = _invoker(handler=handler)
        with pytest.raises(McpArgumentsRefusedError):
            await invoker.invoke(
                tool_name="graph_get",
                arguments={"node_id": "n1", "tenant_id": str(TENANT_ID)},
                request=_request(),
            )
        assert handler.calls == 0

    async def _missing_required() -> None:
        handler = _Handler()
        invoker, _ = _invoker(handler=handler)
        with pytest.raises(McpArgumentsRefusedError):
            await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
        assert handler.calls == 0

    async def _denied() -> None:
        handler = _Handler()
        invoker, _ = _invoker(handler=handler, enforcer=_Enforcer(denies=True))
        with pytest.raises(PermissionDenied):
            await invoker.invoke(
                tool_name="graph_get", arguments={"node_id": "n1"}, request=_request()
            )
        assert handler.calls == 0

    async def _saturated() -> None:
        handler = _Handler()
        gate = ConcurrencyGate(limit=1, wait_timeout=0.02)
        invoker, _ = _invoker(handler=handler, gate=gate)
        async with gate:
            with pytest.raises(ConcurrencyLimitError):
                await invoker.invoke(
                    tool_name="graph_get", arguments={"node_id": "n1"}, request=_request()
                )
        assert handler.calls == 0

    async def _draining() -> None:
        handler = _Handler()
        shutdown = ShutdownCoordinator()
        shutdown.stop_accepting()
        invoker, _ = _invoker(handler=handler, shutdown=shutdown)
        with pytest.raises(ShutdownInProgressError):
            await invoker.invoke(
                tool_name="graph_get", arguments={"node_id": "n1"}, request=_request()
            )
        assert handler.calls == 0

    async def _unknown_tool() -> None:
        handler = _Handler()
        invoker, _ = _invoker(handler=handler)
        with pytest.raises(McpToolDefinitionError):
            await invoker.invoke(tool_name="no_such_tool", arguments={}, request=_request())
        assert handler.calls == 0

    async def _unknown_resource() -> None:
        handler = _Handler()
        invoker, _ = _invoker(resources={})
        with pytest.raises(McpResourceDefinitionError):
            await invoker.invoke_resource(uri="jdlib://nope", request=_request())
        assert handler.calls == 0

    rows = [
        ("an undeclared argument", _undeclared),
        ("a missing required argument", _missing_required),
        ("a denied call", _denied),
        ("a saturated gate", _saturated),
        ("a draining surface", _draining),
        ("an unknown tool", _unknown_tool),
        ("an unknown resource", _unknown_resource),
    ]
    for label, attack in rows:
        # Each row asserts its own refusal *and* its own non-execution, inside the row.
        try:
            await attack()
        except AssertionError as exc:  # a non-execution assertion failed: name the row
            raise AssertionError(f"{label}: {exc}") from exc


async def test_a_deadline_that_fires_is_not_reported_as_nothing_having_run() -> None:
    """A timeout has, by definition, started the work — so it claims neither outcome."""
    handler = _Handler(delay=0.3)
    invoker, emitter = _invoker(handler=handler, timeout=0.05)
    with pytest.raises(McpTimeoutError) as caught:
        await invoker.invoke(tool_name="graph_get", arguments={"node_id": "n1"}, request=_request())
    assert "may or may not have completed" in str(caught.value)
    assert handler.calls == 1
