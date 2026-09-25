"""Neo4j as a first-class data plane (successor §16; directive §8–§17).

A graph is not a second kind of database access — it is the same security model applied to a
different engine. The effective tenant comes from the authenticated context and never from a
request parameter, identifiers are validated values rather than interpolated text, and every
external call sits inside the reliability primitives this library already owns rather than
beside them.

The namespace is additive: nothing here moves the pinned public surface of ``jdlib`` itself.
"""

from jdlib.graph.config import GraphConfig
from jdlib.graph.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphError,
    GraphNotFoundError,
    GraphQueryError,
    GraphTenantViolationError,
    GraphTimeoutError,
    GraphUnavailableError,
    GraphValidationError,
)

__all__ = [
    "GraphAuthorizationError",
    "GraphConfig",
    "GraphConflictError",
    "GraphError",
    "GraphNotFoundError",
    "GraphQueryError",
    "GraphTenantViolationError",
    "GraphTimeoutError",
    "GraphUnavailableError",
    "GraphValidationError",
]
