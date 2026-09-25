"""Neo4j as a first-class data plane (successor §16; directive §8–§17).

A graph is not a second kind of database access — it is the same security model applied to a
different engine. The effective tenant comes from the authenticated context and never from a
request parameter, identifiers are validated values rather than interpolated text, and every
external call sits inside the reliability primitives this library already owns rather than
beside them.

The namespace is additive: nothing here moves the pinned public surface of ``jdlib`` itself.
"""

from jdlib.graph.client import GraphClient, GraphRunner, Neo4jClient, SecretResolver
from jdlib.graph.config import GraphConfig
from jdlib.graph.errors import (
    GraphAuthorizationError,
    GraphCircuitOpenError,
    GraphConflictError,
    GraphError,
    GraphNotFoundError,
    GraphQueryError,
    GraphTenantViolationError,
    GraphTimeoutError,
    GraphUnavailableError,
    GraphValidationError,
)
from jdlib.graph.models import GraphVocabulary, Label, PropertyKey, RelationshipType
from jdlib.graph.policy import GraphCircuitBreaker, GraphPolicy
from jdlib.graph.query import (
    GraphQuery,
    node_create,
    node_delete,
    node_match,
    node_update,
    relationship_create,
    relationship_delete,
    relationship_match,
)
from jdlib.graph.repository import GraphRepository
from jdlib.graph.transaction import GraphTransaction, TransactionOutcome

__all__ = [
    "GraphAuthorizationError",
    "GraphCircuitBreaker",
    "GraphCircuitOpenError",
    "GraphClient",
    "GraphConfig",
    "GraphConflictError",
    "GraphError",
    "GraphNotFoundError",
    "GraphPolicy",
    "GraphQuery",
    "GraphQueryError",
    "GraphRepository",
    "GraphRunner",
    "GraphTenantViolationError",
    "GraphTimeoutError",
    "GraphUnavailableError",
    "GraphTransaction",
    "GraphValidationError",
    "GraphVocabulary",
    "Label",
    "Neo4jClient",
    "PropertyKey",
    "RelationshipType",
    "SecretResolver",
    "TransactionOutcome",
    "node_create",
    "node_delete",
    "node_match",
    "node_update",
    "relationship_create",
    "relationship_delete",
    "relationship_match",
]
