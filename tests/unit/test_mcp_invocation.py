"""Running one tool call: boundary, decision, handler, record (directive §20, §24, §27).

The chain the directive draws is boundary → authorization → operation, and this module is the
part that decides the order and proves the outcomes:

* the boundary runs first, so the context exists before anything is asked about it;
* the tool's *own declared* target is what the authorization question is asked with — the caller
  does not get to name a permission, and the tool does not get to skip its declaration;
* the handler runs inside both scopes — the security context and the tenant context — because the
  library's enforcer reads the tenant from the ambient context, and an operation outside it would
  be an operation under nothing;
* a denial raises before the handler is reached, and the test asserts the handler never ran:
  a refusal that still executed is the worst outcome available, and no exception-type assertion
  can see it;
* a handler's failure is reported as this surface's own error with a generic message, carrying the
  original only as `__cause__`, because §24 keeps the detail inside and the caller outside.

The enforcer is taken as the seam the FastAPI installer takes — `require(permission, target,
session=...)` — so a consumer wires the same object into both surfaces and this module never
learns which implementation it holds.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from jdlib.errors import PermissionDenied
from jdlib.integrations.mcp.errors import McpToolDefinitionError, McpToolExecutionError
from jdlib.integrations.mcp.invocation import McpInvoker
from jdlib.integrations.mcp.tools import McpTool, McpToolRegistry
from jdlib.security.audit.events import AuditOutcome, SecurityEventType
from jdlib.security.context import current_security_context_or_none
from jdlib.tenancy.resolution import RequestInfo
from tests.support.graph_fakes import graph_context

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


class _BoundaryStub:
    """The boundary's contract for this module's purposes: a request in, a context out.

    The boundary's own behaviour — refusals, forged identity, request ids — is pinned by
    `test_mcp_boundary.py`; here it is a collaborator whose only job is to hand back a context.
    """

    def __init__(self) -> None:
        self.seen: list[RequestInfo] = []

    async def establish(self, *, request: RequestInfo) -> Any:
        self.seen.append(request)
        return graph_context(tenant_id=TENANT_ID)


def _request(**headers: str) -> RequestInfo:
    return RequestInfo(
        headers={key.replace("_", "-"): value for key, value in headers.items()},
        query={},
        path="mcp://tool/graph_get",
        host="mcp",
    )


class _Enforcer:
    """The seam: a permission, a target, a session — or a refusal."""

    def __init__(self, *, allow: bool = True) -> None:
        self.allow = allow
        self.calls: list[tuple[str, Any, Any]] = []

    async def require(self, permission: str, target: Any, *, session: Any) -> Any:
        self.calls.append((permission, target, session))
        if not self.allow:
            raise PermissionDenied(f"{permission}: denied by the test double")
        return None


class _Uow:
    def __init__(self) -> None:
        self.opened = 0

    def __call__(self) -> Any:
        self.opened += 1
        return self

    async def __aenter__(self) -> _Uow:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


class _Emitter:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def __call__(self, event: Any) -> None:
        self.events.append(event)


class _Handler:
    def __init__(self, *, result: Any = None, raises: BaseException | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.contexts: list[Any] = []
        self.result = result if result is not None else {"ok": True}
        self.raises = raises

    async def __call__(self, **arguments: Any) -> Any:
        self.calls.append(arguments)
        self.contexts.append(current_security_context_or_none())
        if self.raises is not None:
            raise self.raises
        return self.result


def _invoker(
    handler: _Handler,
    *,
    enforcer: _Enforcer | None = None,
    emitter: _Emitter | None = None,
    public: bool = False,
) -> tuple[McpInvoker, _Enforcer, _Emitter, _Uow]:
    registry = McpToolRegistry()
    registry.register(
        McpTool(
            name="graph_get",
            description="Read one node.",
            handler=handler,
            capability=None if public else "graph:read",
            public=public,
            resource_kind="graph_node",
            action="read",
        )
    )
    the_enforcer = enforcer or _Enforcer()
    the_emitter = emitter or _Emitter()
    uow = _Uow()
    invoker = McpInvoker(
        boundary=_BoundaryStub(),
        registry=registry,
        enforcer=the_enforcer,
        uow_factory=uow,
        emitter=the_emitter,
    )
    return invoker, the_enforcer, the_emitter, uow


async def test_a_permitted_tool_runs_and_returns_its_value() -> None:
    handler = _Handler(result={"node": {"id": "u1"}})
    invoker, enforcer, _, _ = _invoker(handler)
    result = await invoker.invoke(
        tool_name="graph_get",
        arguments={"node_id": "u1"},
        request=_request(authorization="Bearer token-value"),
    )
    assert result == {"node": {"id": "u1"}}
    assert handler.calls == [{"node_id": "u1"}]


async def test_the_handler_runs_inside_the_established_context() -> None:
    """An operation outside the scope is an operation under nothing."""
    handler = _Handler()
    invoker, _, _, _ = _invoker(handler)
    await invoker.invoke(
        tool_name="graph_get",
        arguments={},
        request=_request(authorization="Bearer token-value"),
    )
    seen = handler.contexts[0]
    assert seen is not None
    assert seen.tenant_id == TENANT_ID


async def test_the_tool_is_asked_about_with_its_own_declared_target() -> None:
    handler = _Handler()
    invoker, enforcer, _, uow = _invoker(handler)
    await invoker.invoke(
        tool_name="graph_get",
        arguments={},
        request=_request(authorization="Bearer token-value"),
    )
    permission, target, session = enforcer.calls[0]
    assert permission == "graph:read"
    assert target is not None
    assert session is not None
    assert uow.opened == 1


async def test_a_denied_tool_never_runs() -> None:
    """The non-execution proof: the refusal is not merely reported, it is decisive."""
    handler = _Handler()
    emitter = _Emitter()
    invoker, _, _, _ = _invoker(handler, enforcer=_Enforcer(allow=False), emitter=emitter)
    with pytest.raises(PermissionDenied):
        await invoker.invoke(
            tool_name="graph_get",
            arguments={},
            request=_request(authorization="Bearer token-value"),
        )
    assert handler.calls == []
    assert [event.event_type for event in emitter.events] == [SecurityEventType.AUTHZ_DENY]
    assert emitter.events[0].outcome is AuditOutcome.DENIED


async def test_the_denial_is_audited_with_the_authoritative_actor() -> None:
    handler = _Handler()
    emitter = _Emitter()
    invoker, _, _, _ = _invoker(handler, enforcer=_Enforcer(allow=False), emitter=emitter)
    with pytest.raises(PermissionDenied):
        await invoker.invoke(
            tool_name="graph_get",
            arguments={},
            request=_request(authorization="Bearer token-value"),
        )
    event = emitter.events[0]
    assert event.tenant_id == TENANT_ID
    assert event.principal_id is not None


async def test_a_public_tool_skips_the_question_but_not_the_boundary() -> None:
    """Public means no capability to check — never no context to establish."""
    handler = _Handler()
    invoker, enforcer, _, _ = _invoker(handler, public=True)
    await invoker.invoke(
        tool_name="graph_get",
        arguments={},
        request=_request(authorization="Bearer token-value"),
    )
    assert enforcer.calls == []
    assert len(handler.calls) == 1
    assert handler.contexts[0] is not None


async def test_an_unknown_tool_is_refused_before_anything_is_asked() -> None:
    handler = _Handler()
    invoker, enforcer, _, _ = _invoker(handler)
    with pytest.raises(McpToolDefinitionError):
        await invoker.invoke(
            tool_name="graph_delete",
            arguments={},
            request=_request(authorization="Bearer token-value"),
        )
    assert enforcer.calls == []
    assert handler.calls == []


async def test_a_handler_failure_keeps_its_detail_inside() -> None:
    """§24: the caller gets a safe error; the diagnosis travels as the cause."""
    boom = RuntimeError("dsn=postgresql://user:pw@host/db and a password in the text")
    handler = _Handler(raises=boom)
    invoker, _, _, _ = _invoker(handler)
    with pytest.raises(McpToolExecutionError) as raised:
        await invoker.invoke(
            tool_name="graph_get",
            arguments={},
            request=_request(authorization="Bearer token-value"),
        )
    message = str(raised.value)
    assert "dsn=" not in message
    assert "pw@host" not in message
    assert "RuntimeError" not in message
    assert raised.value.__cause__ is boom


async def test_the_arguments_reach_the_handler_unchanged() -> None:
    handler = _Handler()
    invoker, _, _, _ = _invoker(handler)
    arguments = {"node_id": "u1", "limit": 5, "nested": {"a": [1, 2]}}
    await invoker.invoke(
        tool_name="graph_get",
        arguments=arguments,
        request=_request(authorization="Bearer token-value"),
    )
    assert handler.calls == [arguments]


async def test_a_library_refusal_propagates_unchanged() -> None:
    """A tool that trips a library control reports *that* control, not a generic failure.

    Wrapping everything a handler raises would bury the taxonomy the rest of the library
    speaks — a caller cannot retry a `GraphUnavailableError` it was never shown.
    """
    from jdlib.graph.errors import GraphUnavailableError

    refusal = GraphUnavailableError("the graph is unavailable")
    handler = _Handler(raises=refusal)
    invoker, _, _, _ = _invoker(handler)
    with pytest.raises(GraphUnavailableError) as raised:
        await invoker.invoke(
            tool_name="graph_get",
            arguments={},
            request=_request(authorization="Bearer token-value"),
        )
    assert raised.value is refusal
