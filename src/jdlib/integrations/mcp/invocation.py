"""Running one tool call: boundary, decision, handler, record (directive §20, §24, §27).

The chain the directive draws is boundary → authorization → operation, and this module is the part
that decides the order and makes the outcomes checkable:

* the boundary runs first, so the context exists before anything is asked about it — and so a
  refusal raised a line later still carries an actor;
* the authorization question is asked with the tool's *own declared* target. The caller does not
  name a permission and the tool does not skip its declaration: `McpTool` refuses to exist without
  one, and this module asks for exactly what it declared;
* the handler runs inside both scopes — the security context and the tenant context — because the
  library's enforcer reads the tenant from the ambient context, and an operation outside it would
  be an operation under nothing;
* a denial raises before the handler is reached, and the handler's call count is the proof. A
  refusal that still executed is the worst outcome available, and no assertion on the exception
  type can see it;
* a handler's failure is reported as this surface's own error with a generic message, carrying the
  original only as `__cause__`: §24 keeps the diagnosis inside, where the log and the trace can
  see it, and the caller outside.

The enforcer is taken as the seam the FastAPI installer takes — `require(permission, target,
session=...)` — so a consumer wires the same object into both surfaces and this module never learns
which implementation it holds. One limit is inherited with it: a decision the engine could not make
(degraded) reaches this seam as a denial, because that is the shape the seam raises in; the
`AuthorizationPEP` path is where the library distinguishes the two.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from typing import Any

from jdlib.authz.guards import tenant_target
from jdlib.context import context_scope
from jdlib.errors import JdlibError, PermissionDenied
from jdlib.integrations.mcp.boundary import McpSecurityBoundary
from jdlib.integrations.mcp.errors import McpTimeoutError, McpToolExecutionError
from jdlib.integrations.mcp.tools import McpTool, McpToolRegistry
from jdlib.reliability.concurrency import ConcurrencyGate
from jdlib.reliability.lifecycle import ShutdownCoordinator
from jdlib.security.audit.emitter import SecurityEventEmitter, emit_safely
from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.context import security_context_scope
from jdlib.security.tracing import SecuritySpan, TracerLike, security_span
from jdlib.tenancy.resolution import RequestInfo

#: What a refused tool call is recorded as. The vocabulary already has this event — a tool call
#: the policy said no to *is* an authorization denial — and minting an MCP-shaped second name
#: would split the record an investigation searches.
REFUSAL_EVENT = SecurityEventType.AUTHZ_DENY


class McpInvoker:
    """Runs one tool call through the library's own chain."""

    def __init__(
        self,
        *,
        boundary: McpSecurityBoundary,
        registry: McpToolRegistry,
        enforcer: Any,
        uow_factory: Callable[[], Any] | None = None,
        emitter: SecurityEventEmitter | None = None,
        tracer: TracerLike | None = None,
        gate: ConcurrencyGate | None = None,
        timeout: float | None = None,
        shutdown: ShutdownCoordinator | None = None,
    ) -> None:
        self._boundary = boundary
        self._registry = registry
        self._enforcer = enforcer
        self._uow_factory = uow_factory
        self._emitter = emitter
        self._tracer = tracer
        self._gate = gate
        self._timeout = timeout
        self._shutdown = shutdown

    async def invoke(
        self, *, tool_name: str, arguments: Mapping[str, Any], request: RequestInfo
    ) -> Any:
        """The tool's result, or the refusal that names why it may not have one.

        A tool the registry does not know is refused before anything is asked about it — an
        unknown name is not a permission problem and must not be reported as one.
        """
        if self._shutdown is not None:
            self._shutdown.admit()
        if self._gate is not None:
            async with self._gate:
                return await self._bounded(
                    tool_name=tool_name, arguments=arguments, request=request
                )
        return await self._bounded(tool_name=tool_name, arguments=arguments, request=request)

    async def _bounded(
        self, *, tool_name: str, arguments: Mapping[str, Any], request: RequestInfo
    ) -> Any:
        """The call under its deadline, if it has one."""
        if self._timeout is None:
            return await self._run(tool_name=tool_name, arguments=arguments, request=request)
        try:
            async with asyncio.timeout(self._timeout):
                return await self._run(tool_name=tool_name, arguments=arguments, request=request)
        except TimeoutError as exc:
            raise McpTimeoutError(
                "the call exceeded its deadline; the operation may or may not have completed"
            ) from exc

    async def _run(
        self, *, tool_name: str, arguments: Mapping[str, Any], request: RequestInfo
    ) -> Any:
        """The chain itself: boundary, registry, scopes, decision, handler."""
        with security_span(
            self._tracer,
            "mcp.tool",
            attributes={"security.operation": "mcp.tool", "security.resource": tool_name},
        ) as span:
            context = await self._boundary.establish(request=request)
            tool = self._registry.get(tool_name)
            with security_context_scope(context), context_scope(context.require_tenant()):
                if tool.capability is not None:
                    await self._authorize(tool, span)
                try:
                    result = await tool.handler(**arguments)
                except JdlibError:
                    span.set_attribute("security.result", "failed")
                    raise
                except Exception as exc:
                    span.set_attribute("security.result", "failed")
                    raise McpToolExecutionError("the tool could not complete") from exc
                span.set_attribute("security.result", "ok")
                return result

    async def _authorize(self, tool: McpTool, span: SecuritySpan) -> None:
        """Ask the tool's own declared question, and record a refusal before raising it."""
        try:
            if self._uow_factory is None:
                await self._enforcer.require(tool.capability, tenant_target(), session=None)
            else:
                async with self._uow_factory() as session:
                    await self._enforcer.require(tool.capability, tenant_target(), session=session)
        except PermissionDenied:
            span.set_attribute("security.result", "denied")
            self._record_refusal(tool)
            raise

    def _record_refusal(self, tool: McpTool) -> None:
        """Write the refusal down before it is raised.

        The event fills its actor, tenant and request ids from the ambient context, which is why
        the invocation establishes both scopes before asking. Delivery never changes the outcome:
        an audit outage is not the caller's failure, and the refusal is raised either way.
        """
        emit_safely(
            self._emitter,
            SecurityAuditEvent(
                event_type=REFUSAL_EVENT,
                outcome=AuditOutcome.DENIED,
                action=f"mcp.tool.{tool.name}",
                source=AuditSource.SERVICE,
                resource_type=tool.resource_kind or "mcp-tool",
                metadata={"capability": tool.capability or ""},
            ),
        )
