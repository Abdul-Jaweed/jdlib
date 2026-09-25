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
from typing import Any

from jdlib.graph.errors import GraphError
from jdlib.graph.policy import GraphPolicy
from jdlib.graph.query import GraphQuery
from jdlib.graph.tenant import require_scope, require_tenant_id
from jdlib.security.context import SecurityContext


class TransactionOutcome(StrEnum):
    """How a transaction ended.

    ``PENDING`` is the state it starts in and the only one in which a statement may run.
    """

    PENDING = "pending"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled-back"


class GraphTransaction:
    """An explicit transaction over an injected session."""

    def __init__(self, *, session: Any, context: SecurityContext, policy: GraphPolicy) -> None:
        self._session = session
        self._context = context
        self._policy = policy
        self._tenant_id = require_tenant_id(context)
        self._transaction: Any = None
        self._outcome = TransactionOutcome.PENDING

    @property
    def outcome(self) -> TransactionOutcome:
        return self._outcome

    def retryable(self) -> bool:
        """Whether the work may be attempted again. A committed transaction never is."""
        return self._outcome is not TransactionOutcome.COMMITTED

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
            await self._session.close()
        return False

    async def run(
        self, *, query: GraphQuery, context: SecurityContext
    ) -> list[dict[str, Any]]:
        if self._transaction is None or self._outcome is not TransactionOutcome.PENDING:
            raise GraphError(
                "graph transaction: no statement runs outside a pending transaction"
            )
        require_scope(query=query, context=context, tenant_id=self._tenant_id)
        result = await self._transaction.run(query.text, query.parameters)
        return [dict(record) for record in await result.data()]

    async def commit(self) -> None:
        """End the transaction, keeping its work."""
        if self._outcome is not TransactionOutcome.PENDING:
            raise GraphError("graph transaction: the transaction has already ended")
        await self._transaction.commit()
        self._outcome = TransactionOutcome.COMMITTED

    async def rollback(self) -> None:
        """End the transaction, discarding its work."""
        if self._outcome is not TransactionOutcome.PENDING:
            raise GraphError("graph transaction: the transaction has already ended")
        await self._transaction.rollback()
        self._outcome = TransactionOutcome.ROLLED_BACK
