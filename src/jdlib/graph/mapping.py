"""Driver failures translated into the graph taxonomy (successor §16; directive §15).

One mapper, used by the client and by the transaction, because a failure inside a transaction is
the same failure: two translations would eventually disagree about whether something is retryable.

The driver is imported inside the mapping function rather than at module import: the library must
import without it, and the driver is only present when it has just raised.
"""

from __future__ import annotations

from typing import Any

from jdlib.graph.errors import (
    GraphConflictError,
    GraphError,
    GraphQueryError,
    GraphUnavailableError,
)


def _named(module: Any, *names: str) -> tuple[type[BaseException], ...]:
    """The subset of ``names`` the driver actually defines.

    A driver version that renames one of these degrades to the generic mapping rather than
    raising ``AttributeError`` inside the error path, which is where a second failure is worst.
    """
    found: list[type[BaseException]] = []
    for name in names:
        candidate = getattr(module, name, None)
        if isinstance(candidate, type) and issubclass(candidate, BaseException):
            found.append(candidate)
    return tuple(found)


def map_driver_error(exc: BaseException) -> GraphError:
    """Translate a driver failure into the taxonomy the reliability policy reads.

    The message is the class's, never the driver's: a driver message can quote the statement and
    its literals. The original travels as ``__cause__`` for whoever is debugging.
    """
    try:
        from neo4j import exceptions as driver
    except Exception:  # pragma: no cover - the driver is installed whenever it raised
        return GraphError("graph: the operation failed")
    transient = _named(driver, "ServiceUnavailable", "SessionExpired", "TransientError")
    if isinstance(exc, transient):
        return GraphUnavailableError("graph: the database is unavailable")
    refused = _named(driver, "AuthError", "Unauthorized", "Forbidden")
    if isinstance(exc, refused):
        return GraphUnavailableError(
            "graph: the database refused the connection", transient=False
        )
    if isinstance(exc, _named(driver, "ConstraintError")):
        return GraphConflictError("graph: a constraint refused the write")
    if isinstance(exc, _named(driver, "ClientError", "DatabaseError")):
        return GraphQueryError("graph: the database rejected the statement")
    return GraphError("graph: the operation failed")
