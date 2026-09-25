"""What the MCP surface says about itself, and who it says it was (directive §26, §27).

§26 names the spans, §27 names the audit events, and both end with the same rule in different
words: the telemetry and the trail must carry **authoritative** identity. §27's own sentence is
"never allow MCP callers to forge audit actors", which is a property of *where* the values come
from — the ambient context the invocation established — and not of anything the caller sent.

So these tests pin four things:

* the vocabulary members exist, are grouped as `mcp`, and are pinned by name in the audit-events
  test rather than by relaxing it;
* an event emitted on a refusal or an invocation carries the principal and tenant of the
  *context*, with a caller-supplied `tenant_id`/`actor` in the arguments appearing nowhere;
* a failure is recorded by the error's **class**, never its text — a driver or library message can
  quote a statement and its literals, which is the mistake the graph phase already paid for;
* the span names are the directive's, because a span name is a contract with whoever builds the
  dashboard, and a second name for one thing is a second thing to keep in step.

The tracer is a double here: `SecuritySpan` is inert without one, so "the span exists and is
named" can only be asserted through a tracer that records.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from jdlib.integrations.mcp.boundary import McpSecurityBoundary
from jdlib.integrations.mcp.errors import McpToolExecutionError
from jdlib.integrations.mcp.invocation import McpInvoker
from jdlib.integrations.mcp.resources import tenant_resource
from jdlib.integrations.mcp.tools import McpTool, McpToolRegistry
from jdlib.security.audit.events import AuditOutcome, SecurityEventType
from jdlib.tenancy.resolution import RequestInfo
from tests.support.graph_fakes import graph_context

TENANT_ID = uuid.UUID("66666666-6666-6666-6666-666666666666")


class _Span:
    def __init__(self, recorder: _Tracer, name: str) -> None:
        self._recorder = recorder
        self._name = name

    def __enter__(self) -> _Span:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def set_attribute(self, key: str, value: Any) -> None:
        self._recorder.attributes.append((self._name, key, value))


class _Tracer:
    """A tracer that records: the span seam is inert without one."""

    def __init__(self) -> None:
        self.names: list[str] = []
        self.attributes: list[tuple[str, str, Any]] = []

    def start_span(self, name: str, attributes: dict[str, Any]) -> _Span:
        self.names.append(name)
        return _Span(self, name)


class _Emitter:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def __call__(self, event: Any) -> None:
        self.events.append(event)

    def named(self, event_type: SecurityEventType) -> list[Any]:
        return [event for event in self.events if event.event_type is event_type]


class _Boundary:
    def __init__(self) -> None:
        self.seen: list[RequestInfo] = []

    async def establish(self, *, request: RequestInfo) -> Any:
        self.seen.append(request)
        return graph_context(tenant_id=TENANT_ID)


class _Handler:
    def __init__(self, *, raises: BaseException | None = None) -> None:
        self.calls = 0
        self.raises = raises

    async def __call__(self, **arguments: Any) -> Any:
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        return {"ok": True}


def _request() -> RequestInfo:
    return RequestInfo(
        headers={"authorization": "Bearer fixture-marker"},
        query={},
        path="mcp://tool/graph_get",
        host="mcp",
    )


def _invoker(
    handler: _Handler,
    *,
    emitter: _Emitter | None = None,
    tracer: _Tracer | None = None,
    boundary: _Boundary | None = None,
) -> tuple[McpInvoker, _Emitter, _Tracer]:
    registry = McpToolRegistry()
    registry.register(
        McpTool(
            name="graph_get",
            description="Read one node.",
            handler=handler,
            capability="graph:read",
            resource_kind="graph_node",
            action="read",
        )
    )
    the_emitter = emitter or _Emitter()
    the_tracer = tracer or _Tracer()
    invoker = McpInvoker(
        boundary=boundary or _Boundary(),  # type: ignore[arg-type]
        registry=registry,
        enforcer=_NoEnforcer(),
        emitter=the_emitter,
        tracer=the_tracer,
    )
    return invoker, the_emitter, the_tracer


class _NoEnforcer:
    async def require(self, permission: str, target: Any, *, session: Any) -> Any:
        return None


def test_the_mcp_events_are_in_the_vocabulary_and_grouped_as_mcp() -> None:
    for name in ("MCP_REQUEST", "MCP_TOOL_INVOKED", "MCP_RESOURCE_READ", "MCP_ERROR"):
        member = SecurityEventType[name]
        assert member.category == "mcp", f"{name} is not grouped as mcp"


async def test_an_invocation_is_recorded_with_the_authoritative_actor() -> None:
    handler = _Handler()
    invoker, emitter, _ = _invoker(handler)
    await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    events = emitter.named(SecurityEventType.MCP_TOOL_INVOKED)
    assert len(events) == 1
    event = events[0]
    assert event.action == "mcp.tool.invoked"
    assert event.outcome is AuditOutcome.SUCCESS
    assert event.tenant_id == TENANT_ID
    assert event.principal_id is not None
    assert event.metadata.get("tool") == "graph_get"


async def test_a_forged_identity_never_reaches_the_event() -> None:
    """§27: never allow MCP callers to forge audit actors."""
    handler = _Handler()
    invoker, emitter, _ = _invoker(handler)
    forged = uuid.UUID("99999999-9999-9999-9999-999999999999")
    await invoker.invoke(
        tool_name="graph_get",
        arguments={"tenant_id": str(forged), "actor": str(forged), "principal_id": str(forged)},
        request=_request(),
    )
    event = emitter.named(SecurityEventType.MCP_TOOL_INVOKED)[0]
    assert event.tenant_id == TENANT_ID
    assert event.tenant_id != forged
    assert event.principal_id != forged


async def test_a_denial_is_recorded_under_the_spec_name() -> None:
    """§27 names the event `mcp.authorization.denied`; the action field carries that name."""

    class _Denying:
        async def require(self, permission: str, target: Any, *, session: Any) -> Any:
            from jdlib.errors import PermissionDenied

            raise PermissionDenied("denied by the test double")

    registry = McpToolRegistry()
    handler = _Handler()
    registry.register(
        McpTool(
            name="graph_get",
            description="Read one node.",
            handler=handler,
            capability="graph:read",
            resource_kind="graph_node",
            action="read",
        )
    )
    emitter = _Emitter()
    invoker = McpInvoker(
        boundary=_Boundary(),  # type: ignore[arg-type]
        registry=registry,
        enforcer=_Denying(),
        emitter=emitter,
    )
    from jdlib.errors import PermissionDenied

    with pytest.raises(PermissionDenied):
        await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    events = emitter.named(SecurityEventType.AUTHZ_DENY)
    assert len(events) == 1
    assert events[0].action == "mcp.authorization.denied"
    assert events[0].metadata.get("tool") == "graph_get"
    assert handler.calls == 0


async def test_a_failure_is_recorded_by_class_and_not_by_text() -> None:
    boom = RuntimeError("dsn=postgresql://user:pw@host/db")
    invoker, emitter, _ = _invoker(_Handler(raises=boom))
    with pytest.raises(McpToolExecutionError):
        await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    events = emitter.named(SecurityEventType.MCP_ERROR)
    assert len(events) == 1
    event = events[0]
    assert event.action == "mcp.error"
    assert event.outcome is AuditOutcome.ERROR
    assert event.metadata.get("error") == "RuntimeError"
    rendered = repr(event.metadata)
    assert "dsn=" not in rendered
    assert "pw@host" not in rendered


async def test_the_span_names_are_the_directives() -> None:
    handler = _Handler()
    invoker, _, tracer = _invoker(handler)
    await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    assert "mcp.tool" in tracer.names
    assert "mcp.authorization" in tracer.names


async def test_a_resource_read_is_recorded_and_spanned() -> None:
    emitter = _Emitter()
    tracer = _Tracer()
    registry = _ResourceRegistry()
    registry.register(tenant_resource())
    invoker = McpInvoker(
        boundary=_Boundary(),  # type: ignore[arg-type]
        registry=McpToolRegistry(),
        enforcer=_NoEnforcer(),
        emitter=emitter,
        tracer=tracer,
        resources=registry,
    )
    result = await invoker.invoke_resource(uri="jdlib://tenant", request=_request())
    assert result["tenant_id"] == str(TENANT_ID)
    events = emitter.named(SecurityEventType.MCP_RESOURCE_READ)
    assert len(events) == 1
    assert events[0].action == "mcp.resource.read"
    assert "mcp.resource" in tracer.names


async def test_an_established_request_is_recorded_inside_the_scope() -> None:
    """A refusal or a start recorded one line before the scope carries an empty actor."""
    emitter = _Emitter()
    boundary = McpSecurityBoundary(
        principal_provider=_Provider(),  # type: ignore[arg-type]
        chain=_Chain(),  # type: ignore[arg-type]
        factory=_Factory(),  # type: ignore[arg-type]
        emitter=emitter,
    )
    await boundary.establish(request=_request())
    events = emitter.named(SecurityEventType.MCP_REQUEST)
    assert len(events) == 1
    assert events[0].tenant_id == TENANT_ID
    assert events[0].principal_id is not None
    assert events[0].action == "mcp.request"


class _Provider:
    async def __call__(self, request: RequestInfo) -> Any:
        return graph_context(tenant_id=TENANT_ID).principal


class _Chain:
    async def resolve(self, request: RequestInfo, principal: Any) -> Any:
        from jdlib.context import TenantRef

        return TenantRef(id=TENANT_ID, slug="acme")


class _Factory:
    async def for_principal(self, principal: Any, tenant_ref: Any, **kwargs: Any) -> Any:
        from jdlib.context import PlacementStrategy, TenantContext

        return TenantContext(
            tenant_id=tenant_ref.id,
            tenant_slug=tenant_ref.slug or "acme",
            strategy=PlacementStrategy.SHARED,
            principal=principal,
            request_id=kwargs.get("request_id") or "req-1",
            correlation_id=kwargs.get("correlation_id") or kwargs.get("request_id") or "corr-1",
            trace_id=kwargs.get("trace_id"),
        )


class _ResourceRegistry:
    def __init__(self) -> None:
        self._resources: dict[str, Any] = {}

    def register(self, resource: Any) -> Any:
        self._resources[resource.uri] = resource
        return resource

    def get(self, uri: str) -> Any:
        from jdlib.integrations.mcp.errors import McpResourceDefinitionError

        resource = self._resources.get(uri)
        if resource is None:
            raise McpResourceDefinitionError(f"no resource at {uri}")
        return resource
