"""One transaction: statements inside it, one ending, and no retry after a commit (directive §14).

A transaction is where a scope check gets forgotten, so the tenant check the client applies is
applied here too, through the same helper. And a transaction that committed must never be
repeated — repeating a committed write is how a duplicate appears — so this object records how
it ended and answers whether it may be retried: the policy asks a fact rather than assuming one.

The class is written against the *shape* of the driver's session and transaction — begin, run,
commit, rollback, close — rather than against the driver itself, which is what lets the unit
layer hold it with no database client installed.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any

from jdlib.graph.errors import GraphError
from jdlib.graph.mapping import map_driver_error
from jdlib.graph.query import GraphQuery
from jdlib.graph.tenant import require_scope, require_tenant_id
from jdlib.security.audit.emitter import SecurityEventEmitter
from jdlib.security.context import SecurityContext, security_context_scope
from jdlib.security.tracing import SecuritySpan, TracerLike, security_span

if TYPE_CHECKING:
    from jdlib.graph.policy import GraphPolicy


class TransactionOutcome(StrEnum):
    """How a transaction ended.

    ``PENDING`` is the state it starts in and the only one in which a statement may run.
    ``UNCERTAIN`` is the state a transaction enters when its commit failed: the server may have
    applied it before the error arrived, so it is not the same thing as a rollback and must not
    be treated as one.
    """

    PENDING = "pending"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled-back"
    UNCERTAIN = "uncertain"


class GraphTransaction:
    """An explicit transaction over an injected session."""

    def __init__(
        self,
        *,
        session: Any,
        context: SecurityContext,
        policy: GraphPolicy,
        tracer: TracerLike | None = None,
        emitter: SecurityEventEmitter | None = None,
    ) -> None:
        self._session = session
        self._context = context
        self._policy = policy
        self._tracer = tracer
        self._emitter = emitter
        self._tenant_id = require_tenant_id(context)
        self._transaction: Any = None
        self._outcome = TransactionOutcome.PENDING
        self._span: SecuritySpan = security_span(
            tracer, "graph.transaction", attributes={"security.operation": "graph.transaction"}
        )

    @property
    def outcome(self) -> TransactionOutcome:
        return self._outcome

    def retryable(self) -> bool:
        """Whether the work may be attempted again.

        True only when nothing can have landed: a transaction that never began, or one that was
        rolled back. A commit that *failed* leaves the outcome uncertain — the server may have
        applied it before the error arrived — and an uncertain write is not repeated, because
        repeating it is how a duplicate appears.
        """
        return self._outcome in (TransactionOutcome.PENDING, TransactionOutcome.ROLLED_BACK)

    async def __aenter__(self) -> GraphTransaction:
        self._transaction = await self._session.begin_transaction(
            timeout=self._policy.statement_timeout
        )
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> bool:
        try:
            if self._outcome is TransactionOutcome.PENDING:
                if exc_type is None:
                    await self.commit()
                else:
                    await self.rollback()
        finally:
            self._span.set_attribute("security.outcome", self._outcome.value)
            self._span.end()
            await self._session.close()
        return False

    async def run(
        self, *, query: GraphQuery, context: SecurityContext
    ) -> list[dict[str, Any]]:
        if self._transaction is None or self._outcome is not TransactionOutcome.PENDING:
            raise GraphError(
                "graph transaction: no statement runs outside a pending transaction"
            )
        with security_context_scope(context):
            require_scope(
                query=query,
                context=context,
                tenant_id=self._tenant_id,
                emitter=self._emitter,
                action="graph.transaction",
            )
            try:
                result = await self._transaction.run(query.text, query.parameters)
            except GraphError:
                raise
            except Exception as exc:
                raise map_driver_error(exc) from exc
        return [dict(record) for record in await result.data()]

    async def commit(self) -> None:
        """End the transaction, keeping its work.

        A commit that fails leaves the outcome ``UNCERTAIN`` rather than pending: the server may
        have applied the transaction before the error arrived, and the difference between
        "definitely not applied" and "unknown" is the difference between a safe retry and a
        duplicate write.
        """
        if self._outcome is not TransactionOutcome.PENDING:
            raise GraphError("graph transaction: the transaction has already ended")
        try:
            await self._transaction.commit()
        except Exception:
            self._outcome = TransactionOutcome.UNCERTAIN
            raise
        self._outcome = TransactionOutcome.COMMITTED

    async def rollback(self) -> None:
        """End the transaction, discarding its work."""
        if self._outcome is not TransactionOutcome.PENDING:
            raise GraphError("graph transaction: the transaction has already ended")
        await self._transaction.rollback()
        self._outcome = TransactionOutcome.ROLLED_BACK
