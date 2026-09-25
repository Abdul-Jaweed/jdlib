"""The invocation path under load: drain, saturation and deadlines (directive §25).

§25 asks for timeouts, concurrency limits and graceful shutdown. Each of the three is already
implemented — `ShutdownCoordinator`, the concurrency gate, `asyncio` — so this module is about
where they attach, and every one of them attaches *before* the handler:

* a surface that has begun draining refuses new work, and the refusal happens before the handler
  runs, so "shutting down" never means "started anyway";
* a saturated gate refuses the call rather than queueing it, with the same non-execution proof;
* the deadline bounds the whole call, because the caller's deadline is for the call and not for
  the parts of it that happened to be slow. A timeout is **not** a tool failure: the operation may
  or may not have completed, and that difference is exactly the one the graph's `UNCERTAIN`
  outcome exists to preserve, so the error says so rather than inviting a blind retry;
* with none of the three configured, the invocation behaves exactly as it did before — the
  defaults are the previous behaviour, and a test says so.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest

from jdlib.integrations.mcp.errors import McpTimeoutError, McpToolExecutionError
from jdlib.integrations.mcp.invocation import McpInvoker
from jdlib.integrations.mcp.tools import McpTool, McpToolRegistry
from jdlib.reliability.concurrency import ConcurrencyGate, ConcurrencyLimitError
from jdlib.reliability.lifecycle import ShutdownCoordinator, ShutdownInProgressError
from jdlib.tenancy.resolution import RequestInfo
from tests.support.graph_fakes import graph_context

TENANT_ID = uuid.UUID("55555555-5555-5555-5555-555555555555")


class _Boundary:
    async def establish(self, *, request: RequestInfo) -> Any:
        return graph_context(tenant_id=TENANT_ID)


class _Enforcer:
    async def require(self, permission: str, target: Any, *, session: Any) -> Any:
        return None


class _Handler:
    def __init__(self, *, delay: float = 0.0, result: Any = None) -> None:
        self.calls = 0
        self.delay = delay
        self.result = {"ok": True} if result is None else result

    async def __call__(self, **arguments: Any) -> Any:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.result


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
    gate: ConcurrencyGate | None = None,
    timeout: float | None = None,
    shutdown: ShutdownCoordinator | None = None,
) -> McpInvoker:
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
    return McpInvoker(
        boundary=_Boundary(),  # type: ignore[arg-type]
        registry=registry,
        enforcer=_Enforcer(),
        gate=gate,
        timeout=timeout,
        shutdown=shutdown,
    )


async def test_a_draining_surface_refuses_before_the_handler_runs() -> None:
    """Shutting down never means "started anyway"."""
    handler = _Handler()
    shutdown = ShutdownCoordinator()
    shutdown.stop_accepting()
    invoker = _invoker(handler, shutdown=shutdown)
    with pytest.raises(ShutdownInProgressError):
        await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    assert handler.calls == 0


async def test_a_saturated_surface_refuses_before_the_handler_runs() -> None:
    handler = _Handler()
    gate = ConcurrencyGate(limit=1, wait_timeout=0.02)
    invoker = _invoker(handler, gate=gate)
    async with gate:
        with pytest.raises(ConcurrencyLimitError):
            await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    assert handler.calls == 0


async def test_the_deadline_bounds_the_whole_call() -> None:
    handler = _Handler(delay=0.3)
    invoker = _invoker(handler, timeout=0.05)
    with pytest.raises(McpTimeoutError):
        await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())


async def test_a_call_within_the_deadline_succeeds() -> None:
    handler = _Handler(delay=0.01)
    invoker = _invoker(handler, timeout=1.0)
    result = await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    assert result == {"ok": True}


async def test_a_timeout_is_not_reported_as_a_tool_failure() -> None:
    """The operation may or may not have completed; the error must not invite a blind retry."""
    handler = _Handler(delay=0.3)
    invoker = _invoker(handler, timeout=0.05)
    with pytest.raises(McpTimeoutError) as raised:
        await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    assert not isinstance(raised.value, McpToolExecutionError)
    assert "may or may not" in str(raised.value)


async def test_the_gate_releases_its_slot_after_the_call() -> None:
    handler = _Handler()
    gate = ConcurrencyGate(limit=1, wait_timeout=0.02)
    invoker = _invoker(handler, gate=gate)
    await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    assert gate.in_flight == 0
    await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    assert handler.calls == 2  # the second call was admitted, so the slot was released


async def test_the_gate_releases_its_slot_when_the_call_is_refused() -> None:
    handler = _Handler()
    gate = ConcurrencyGate(limit=1, wait_timeout=0.02)
    shutdown = ShutdownCoordinator()
    invoker = _invoker(handler, gate=gate, shutdown=shutdown)
    shutdown.stop_accepting()
    with pytest.raises(ShutdownInProgressError):
        await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    assert gate.in_flight == 0


async def test_with_none_configured_the_invocation_behaves_as_before() -> None:
    """Additive means the defaults are the previous behaviour, not a new one."""
    handler = _Handler()
    invoker = _invoker(handler)
    first = await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    second = await invoker.invoke(tool_name="graph_get", arguments={}, request=_request())
    assert first == {"ok": True}
    assert second == {"ok": True}
    assert handler.calls == 2
