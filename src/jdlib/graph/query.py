"""The restricted graph API: what may be asked of the database, and how (directive §13).

Every builder here emits text whose *only* interpolated parts are validated identifiers, and
binds everything else as a parameter. The tenant is bound, never written into the statement, so
no caller can name a tenant in a query; and every relationship builder scopes both endpoints
with the same parameter, so a cross-tenant edge cannot be expressed even by accident.

`GraphQuery` carries its text and its parameters as one value, for the same reason the SQL
compiler does: neither is usable without the other, so a caller cannot run the statement with
the values interpolated or reuse the parameters against different text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from jdlib.graph.errors import GraphValidationError
from jdlib.graph.models import Label, PropertyKey, RelationshipType

#: The parameter every operation binds its tenant to. Distinctive on purpose: a name that could
#: collide with an application's own parameter is a name an attacker could try to shadow.
TENANT_PARAMETER = "jdlib_scope_tenant"
#: The property that carries the tenant boundary, and the one that carries identity. Both are
#: set by the operation rather than accepted from a caller, so neither can be forged.
TENANT_PROPERTY = "tenant_id"
ID_PROPERTY = "id"

_ID_PARAMETER = "jdlib_node_id"
_FROM_PARAMETER = "jdlib_from_id"
_TO_PARAMETER = "jdlib_to_id"
_PROPERTIES_PARAMETER = "jdlib_properties"

RESERVED_PROPERTY_KEYS = frozenset({TENANT_PROPERTY, ID_PROPERTY})


@dataclass(frozen=True, slots=True)
class GraphQuery:
    """Text and its bound parameters as one value."""

    text: str
    parameters: dict[str, object] = field(default_factory=dict)

    def __repr__(self) -> str:
        # The text is safe to render - it holds identifiers and parameter names - and the values
        # are not, so only one of the two is ever printed.
        return f"GraphQuery(text={self.text!r}, values=[REDACTED])"


def _label(value: object) -> Label:
    """A label that came through the vocabulary, or a refusal.

    The annotation says `Label`; the annotation is not enforcement. A plain string in this
    position is interpolated straight into the pattern, so `"User) DETACH DELETE n //"` would
    become Cypher and comment out the tenant predicate that follows it. The type is checked at
    the position, before any statement exists.
    """
    if not isinstance(value, Label):
        raise GraphValidationError("node labels must be Label values obtained from the vocabulary")
    return value


def _relationship_type(value: object) -> RelationshipType:
    """The relationship type sits inside the arrow, where a `>` closes the pattern."""
    if not isinstance(value, RelationshipType):
        raise GraphValidationError(
            "relationship types must be RelationshipType values obtained from the vocabulary"
        )
    return value


def _tenant(tenant: object) -> dict[str, object]:
    if not isinstance(tenant, str) or not tenant:
        raise GraphValidationError("a graph operation needs the authoritative tenant")
    return {TENANT_PARAMETER: tenant}


def _properties(properties: Mapping[PropertyKey, object] | None) -> dict[str, object]:
    """Refuse anything that is not a `PropertyKey`, and anything reserved for the operation."""
    collected: dict[str, object] = {}
    for key, value in (properties or {}).items():
        if not isinstance(key, PropertyKey):
            raise GraphValidationError("property keys must be PropertyKey values")
        if key.value in RESERVED_PROPERTY_KEYS:
            raise GraphValidationError(
                f"{key.value} is set by the operation, not by the caller"
            )
        collected[key.value] = value
    return collected


def node_match(label: Label, *, tenant: str, node_id: str) -> GraphQuery:
    """Select one node, by label and identity, inside the caller's tenant."""
    label = _label(label)
    text = (
        f"MATCH (n:{label}) WHERE n.{TENANT_PROPERTY} = ${TENANT_PARAMETER} "
        f"AND n.{ID_PROPERTY} = ${_ID_PARAMETER} RETURN n"
    )
    return GraphQuery(text, {**_tenant(tenant), _ID_PARAMETER: node_id})


def node_create(
    label: Label,
    *,
    tenant: str,
    node_id: str,
    properties: Mapping[PropertyKey, object] | None = None,
) -> GraphQuery:
    """Create one node. The tenant and the identity are assigned last, and cannot be supplied."""
    label = _label(label)
    text = (
        f"CREATE (n:{label}) SET n = ${_PROPERTIES_PARAMETER} "
        f"SET n.{TENANT_PROPERTY} = ${TENANT_PARAMETER}, "
        f"n.{ID_PROPERTY} = ${_ID_PARAMETER} RETURN n"
    )
    return GraphQuery(
        text,
        {**_tenant(tenant), _ID_PARAMETER: node_id, _PROPERTIES_PARAMETER: _properties(properties)},
    )


def node_update(
    label: Label,
    *,
    tenant: str,
    node_id: str,
    properties: Mapping[PropertyKey, object] | None = None,
) -> GraphQuery:
    """Merge properties into one node inside the caller's tenant. Identity is not touched."""
    label = _label(label)
    text = (
        f"MATCH (n:{label}) WHERE n.{TENANT_PROPERTY} = ${TENANT_PARAMETER} "
        f"AND n.{ID_PROPERTY} = ${_ID_PARAMETER} SET n += ${_PROPERTIES_PARAMETER} RETURN n"
    )
    return GraphQuery(
        text,
        {**_tenant(tenant), _ID_PARAMETER: node_id, _PROPERTIES_PARAMETER: _properties(properties)},
    )


def node_delete(
    label: Label, *, tenant: str, node_id: str, detach: bool = False
) -> GraphQuery:
    """Delete one node inside the caller's tenant.

    ``DELETE`` by default: a node that still has relationships refuses to disappear with them,
    so removing a connected node is two deliberate operations rather than one that silently
    takes the edges with it. ``detach=True`` is the explicit way to ask for the other shape.
    """
    label = _label(label)
    keyword = "DETACH DELETE" if detach else "DELETE"
    text = (
        f"MATCH (n:{label}) WHERE n.{TENANT_PROPERTY} = ${TENANT_PARAMETER} "
        f"AND n.{ID_PROPERTY} = ${_ID_PARAMETER} {keyword} n"
    )
    return GraphQuery(text, {**_tenant(tenant), _ID_PARAMETER: node_id})


def relationship_match(
    relationship: RelationshipType,
    *,
    tenant: str,
    from_label: Label,
    from_id: str,
    to_label: Label,
    to_id: str,
) -> GraphQuery:
    """Select one relationship, with *both* endpoints scoped to the caller's tenant."""
    relationship = _relationship_type(relationship)
    from_label = _label(from_label)
    to_label = _label(to_label)
    text = (
        f"MATCH (a:{from_label})-[r:{relationship}]->(b:{to_label}) "
        f"WHERE a.{TENANT_PROPERTY} = ${TENANT_PARAMETER} AND a.{ID_PROPERTY} = ${_FROM_PARAMETER} "
        f"AND b.{TENANT_PROPERTY} = ${TENANT_PARAMETER} AND b.{ID_PROPERTY} = ${_TO_PARAMETER} "
        "RETURN r"
    )
    return GraphQuery(
        text,
        {**_tenant(tenant), _FROM_PARAMETER: from_id, _TO_PARAMETER: to_id},
    )


def relationship_create(
    relationship: RelationshipType,
    *,
    tenant: str,
    from_label: Label,
    from_id: str,
    to_label: Label,
    to_id: str,
    properties: Mapping[PropertyKey, object] | None = None,
) -> GraphQuery:
    """Create one relationship between two nodes of the caller's tenant.

    `MERGE` rather than `CREATE`: creating the same edge twice is a no-op, which is what makes
    a retried write safe to repeat. Both endpoints must match under the *same* tenant parameter,
    so an edge that would cross a tenant boundary simply has no endpoints to attach to.
    """
    relationship = _relationship_type(relationship)
    from_label = _label(from_label)
    to_label = _label(to_label)
    text = (
        f"MATCH (a:{from_label}), (b:{to_label}) "
        f"WHERE a.{TENANT_PROPERTY} = ${TENANT_PARAMETER} AND a.{ID_PROPERTY} = ${_FROM_PARAMETER} "
        f"AND b.{TENANT_PROPERTY} = ${TENANT_PARAMETER} AND b.{ID_PROPERTY} = ${_TO_PARAMETER} "
        f"MERGE (a)-[r:{relationship}]->(b) SET r += ${_PROPERTIES_PARAMETER} RETURN r"
    )
    return GraphQuery(
        text,
        {
            **_tenant(tenant),
            _FROM_PARAMETER: from_id,
            _TO_PARAMETER: to_id,
            _PROPERTIES_PARAMETER: _properties(properties),
        },
    )


def relationship_delete(
    relationship: RelationshipType,
    *,
    tenant: str,
    from_label: Label,
    from_id: str,
    to_label: Label,
    to_id: str,
) -> GraphQuery:
    """Delete one relationship, with both endpoints scoped to the caller's tenant."""
    relationship = _relationship_type(relationship)
    from_label = _label(from_label)
    to_label = _label(to_label)
    text = (
        f"MATCH (a:{from_label})-[r:{relationship}]->(b:{to_label}) "
        f"WHERE a.{TENANT_PROPERTY} = ${TENANT_PARAMETER} AND a.{ID_PROPERTY} = ${_FROM_PARAMETER} "
        f"AND b.{TENANT_PROPERTY} = ${TENANT_PARAMETER} AND b.{ID_PROPERTY} = ${_TO_PARAMETER} "
        "DELETE r"
    )
    return GraphQuery(
        text,
        {**_tenant(tenant), _FROM_PARAMETER: from_id, _TO_PARAMETER: to_id},
    )
