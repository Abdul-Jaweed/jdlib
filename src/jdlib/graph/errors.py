"""The graph error taxonomy (successor §16; directive §15).

One class per outcome the reliability policy has to tell apart, because the policy's first
question — may this be retried? — is answered by the taxonomy before it is answered by the
operation. The failures that are *decisions* (a refusal, a validation, a missing node, a
constraint) are permanent by construction; the one that is *weather* (an unreachable or
exhausted dependency) is transient by construction; and a timeout is neither until the
operation says so, because repeating a write whose outcome is unknown is how a duplicate
appears.
"""

from __future__ import annotations

from jdlib.errors import JdlibError


class GraphError(JdlibError):
    """Base for graph failures.

    ``transient`` says whether the failure is worth another attempt. The reliability policy
    consults the library's own ``is_retryable`` first and falls back to this flag, exactly as it
    does for the connector framework, so a failure the taxonomy already understands is
    classified once and not twice.
    """

    def __init__(self, *args: object, transient: bool = False) -> None:
        super().__init__(*args)
        self.transient = transient


class GraphValidationError(GraphError, ValueError):
    """A value was refused before it reached the database.

    Also a ``ValueError``, so a caller doing ordinary argument validation catches it either way.
    """


class GraphAuthorizationError(GraphError):
    """The caller's context does not authorize this operation, or cannot be verified."""


class GraphTenantViolationError(GraphError):
    """An operation tried to cross a tenant boundary, and was refused."""


class GraphNotFoundError(GraphError):
    """The node or relationship is not there.

    Distinct from "the database is unreachable", which is not a 404 and must not read as one.
    """


class GraphConflictError(GraphError):
    """A constraint refused the write: a duplicate, or a relationship with a missing endpoint."""


class GraphQueryError(GraphError):
    """The database rejected the statement: syntax, types, an unknown procedure."""


class GraphTimeoutError(GraphError):
    """An operation exceeded its deadline.

    Not transient by default: the outcome of a timed-out write is unknown, and the policy must
    not repeat it. An operation whose retry is known to be safe passes ``transient=True``.
    """


class GraphUnavailableError(GraphError):
    """The database is unreachable, its pool is exhausted, or it refused the connection.

    Transient by construction, because that is the common case — and explicitly overridable,
    because a rejected credential or an unsupported server version is the same shape of failure
    with a permanent cause, and retrying it forever is how a dependency outage becomes an
    outage of this service too.
    """

    def __init__(self, *args: object, transient: bool = True) -> None:
        super().__init__(*args, transient=transient)


class GraphCircuitOpenError(GraphError):
    """The circuit is open after repeated failures: the call was refused without attempting.

    Permanent by construction — the point of the breaker is to stop asking — and distinct from
    :class:`GraphUnavailableError` so a caller can tell "the dependency answered badly" from
    "we stopped asking".
    """
