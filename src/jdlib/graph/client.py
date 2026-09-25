"""The Neo4j client: what it holds, what it refuses, and what it maps (directive §10–§11, §15).

The adapter follows the connector idiom — a target built at open, an injected policy, a health
probe that answers a boolean — with three properties of its own:

* the driver is imported inside :meth:`Neo4jClient.open`, so ``import jdlib.graph`` costs nothing
  and the optional dependency stays optional;
* credentials are resolved through the provider chain at open and handed to the driver, never
  stored on the client or on the config, so neither can render one;
* every statement is checked against the authenticated tenant before it runs. The client is open
  for one tenant, and a statement bound to another is refused with nothing reaching the driver —
  the last point at which both the context and the statement are visible.

Driver failures are mapped into the graph taxonomy, and no driver message is interpolated into a
graph error: a driver message can quote the statement it rejected.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Protocol, runtime_checkable

from jdlib.credentials import ResolvedSecret, SecretRef
from jdlib.graph.config import GraphConfig
from jdlib.graph.errors import (
    GraphError,
    GraphQueryError,
    GraphTenantViolationError,
    GraphTimeoutError,
)
from jdlib.graph.mapping import map_driver_error
from jdlib.graph.policy import GraphPolicy
from jdlib.graph.query import GraphQuery
from jdlib.graph.tenant import require_open_tenant, require_scope
from jdlib.graph.transaction import GraphTransaction
from jdlib.security.audit.emitter import SecurityEventEmitter, emit_safely
from jdlib.security.audit.events import (
    AuditOutcome,
    AuditSource,
    SecurityAuditEvent,
    SecurityEventType,
)
from jdlib.security.context import SecurityContext, security_context_scope
from jdlib.security.tracing import SecuritySpan, TracerLike, security_span


class SecretResolver(Protocol):
    """What the client needs from the credential chain: a reference, resolved to a value."""

    def resolve(self, ref: SecretRef) -> ResolvedSecret: ...


@runtime_checkable
class GraphRunner(Protocol):
    """What running a statement needs — a client, or a transaction inside one."""

    async def run(
        self, *, query: GraphQuery, context: SecurityContext
    ) -> list[dict[str, Any]]: ...


@runtime_checkable
class GraphClient(GraphRunner, Protocol):
    """A runner that can also be opened, closed, asked about its health, and begin a transaction."""

    async def open(self, *, context: SecurityContext) -> None: ...

    async def close(self) -> None: ...

    async def health(self) -> bool: ...

    def begin(self, *, context: SecurityContext) -> GraphTransaction: ...


class Neo4jClient:
    """The verified Neo4j adapter over the library's own credential and reliability seams."""

    def __init__(
        self,
        config: GraphConfig,
        *,
        provider: SecretResolver,
        policy: GraphPolicy | None = None,
        driver_factory: Callable[..., Any] | None = None,
        tracer: TracerLike | None = None,
        emitter: SecurityEventEmitter | None = None,
    ) -> None:
        self._config = config
        self._provider = provider
        self._policy = policy or GraphPolicy()
        self._driver_factory = driver_factory
        self._tracer = tracer
        self._emitter = emitter
        self._driver: Any = None
        self._tenant_id: str | None = None

    async def open(self, *, context: SecurityContext) -> None:
        tenant = context.require_tenant()
        factory = self._driver_factory or _driver_factory()
        self._driver = factory(self._config.uri, auth=self._auth(), **self._bounds())
        self._tenant_id = str(tenant.tenant_id)

    def begin(self, *, context: SecurityContext) -> GraphTransaction:
        """Open an explicit transaction for this tenant.

        The context is checked here as well as per statement: a client opened for one tenant does
        not begin a transaction for another, and the transaction carries the tenant it was opened
        with so its own statements are checked against it too.
        """
        if self._driver is None:
            raise GraphError("graph client: begin before open")
        with security_context_scope(context):
            require_open_tenant(
                context, self._tenant_id, emitter=self._emitter, action="graph.begin"
            )
        return GraphTransaction(
            session=self._driver.session(database=self._config.database),
            context=context,
            policy=self._policy,
            tracer=self._tracer,
            emitter=self._emitter,
        )

    @asynccontextmanager
    async def opened(self, *, context: SecurityContext) -> AsyncIterator[Neo4jClient]:
        await self.open(context=context)
        try:
            yield self
        finally:
            await self.close()

    async def close(self) -> None:
        if self._driver is not None:
            await self._driver.close()
            self._driver = None
        self._tenant_id = None

    async def health(self) -> bool:
        if self._driver is None:
            return False
        try:
            await self._driver.verify_connectivity()
        except Exception:
            return False
        return True

    async def run(
        self, *, query: GraphQuery, context: SecurityContext
    ) -> list[dict[str, Any]]:
        if self._driver is None:
            raise GraphError("graph client: run before open")
        with security_span(
            self._tracer, "graph.run", attributes={"security.operation": "graph.run"}
        ) as span, security_context_scope(context):
            # The scope is what attributes anything written from here: a refusal recorded with no
            # actor is not evidence, and the event fills its actor from the ambient context.
            try:
                require_scope(
                    query=query,
                    context=context,
                    tenant_id=self._tenant_id,
                    emitter=self._emitter,
                    action="graph.run",
                )
            except GraphTenantViolationError:
                span.set_attribute("security.result", "refused")
                raise
            try:
                rows = await asyncio.wait_for(
                    self._execute(query), timeout=self._policy.statement_timeout
                )
            except TimeoutError as exc:
                span.set_attribute("security.result", "timeout")
                raise GraphTimeoutError(
                    "graph client: the statement exceeded its deadline"
                ) from exc
            except GraphError:
                span.set_attribute("security.result", "failed")
                raise
            except Exception as exc:
                mapped = map_driver_error(exc)
                self._record_rejection(mapped, span)
                raise mapped from exc
            span.set_attribute("security.result", "ok")
            return rows

    def _record_rejection(self, error: GraphError, span: SecuritySpan) -> None:
        """A statement the database refused is a security-relevant event; the rest are noise."""
        span.set_attribute("security.result", "failed")
        if not isinstance(error, GraphQueryError):
            return
        emit_safely(
            self._emitter,
            SecurityAuditEvent(
                event_type=SecurityEventType.QUERY_REJECTED,
                outcome=AuditOutcome.ERROR,
                action="graph.run",
                source=AuditSource.SERVICE,
                resource_type="graph-statement",
                metadata={"error": type(error).__name__},
            ),
        )

    async def _execute(self, query: GraphQuery) -> list[dict[str, Any]]:
        async with self._driver.session(database=self._config.database) as session:
            result = await session.run(
                query.text, query.parameters, timeout=self._policy.statement_timeout
            )
            return [dict(record) for record in await result.data()]

    def _auth(self) -> tuple[str, str] | None:
        if self._config.auth is None:
            return None
        resolved = self._provider.resolve(self._config.auth)
        if self._config.username is not None:
            return (self._config.username, resolved.value)
        return ("bearer", resolved.value)

    def _bounds(self) -> dict[str, Any]:
        return {
            "max_connection_pool_size": self._config.max_connection_pool_size,
            "connection_acquisition_timeout": self._config.connection_acquisition_timeout,
            "max_connection_lifetime": self._config.max_connection_lifetime,
            "connection_timeout": self._config.connection_timeout,
            "max_transaction_retry_time": self._config.max_transaction_retry_time,
        }


def _driver_factory() -> Callable[..., Any]:
    """The real factory, imported here so the library's own import stays driver-free."""
    from neo4j import AsyncGraphDatabase

    factory: Callable[..., Any] = AsyncGraphDatabase.driver
    return factory
