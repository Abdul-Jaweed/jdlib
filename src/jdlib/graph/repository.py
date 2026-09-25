"""The tenant-scoped graph operations (successor §16; directive §11–§12).

The tenant is not a parameter of any method here. It is read from the authenticated context —
``context.require_tenant()`` — and the client re-checks the statement against that same context
before it runs, so there is no argument in which a caller could name another tenant, and no path
by which a forgotten scope becomes a cross-tenant read.

Identifiers are obtained through the vocabulary rather than assembled from strings, so an
undeclared label, relationship type or property key is refused before a statement exists. Values
— identities and properties — are bound as parameters, so no value can change a statement.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from jdlib.graph.client import GraphClient
from jdlib.graph.errors import GraphValidationError
from jdlib.graph.models import GraphVocabulary, PropertyKey
from jdlib.graph.query import (
    node_create,
    node_delete,
    node_match,
    node_update,
    relationship_create,
    relationship_delete,
    relationship_match,
)
from jdlib.security.context import SecurityContext

#: A node identity is a value, not an identifier: it is bound, so it cannot change a statement.
#: The pattern is hygiene rather than security — it keeps a typo loud and a log line short — and
#: it is stated here rather than inherited from the driver's own limits.
_ID_PATTERN = re.compile(r"[A-Za-z0-9_.:@-]{1,256}\Z")


def _require_id(value: str, what: str) -> str:
    if not isinstance(value, str) or not _ID_PATTERN.match(value):
        raise GraphValidationError(
            f"{what} must be a non-empty name of letters, digits, dot, colon, dash, "
            "underscore or at-sign"
        )
    return value


def _node_of(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    node = rows[0].get("n")
    return dict(node) if isinstance(node, Mapping) else None


def _edge_of(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not rows:
        return None
    edge = rows[0].get("r")
    return dict(edge) if isinstance(edge, Mapping) else None


class GraphRepository:
    """Tenant-scoped node and relationship operations over a :class:`GraphClient`.

    The repository is the recommended surface for an application: it takes plain strings for
    labels and property keys, resolves them against the vocabulary it was given, and derives the
    tenant from the context of each call.
    """

    def __init__(self, *, client: GraphClient, vocabulary: GraphVocabulary) -> None:
        self._client = client
        self._vocabulary = vocabulary

    # -- Nodes --------------------------------------------------------------

    async def create_node(
        self,
        *,
        context: SecurityContext,
        label: str,
        node_id: str,
        properties: Mapping[str, object] | None = None,
    ) -> None:
        """Create one node. Its tenant and its identity are set by the operation."""
        query = node_create(
            self._vocabulary.label(label),
            tenant=self._tenant(context),
            node_id=_require_id(node_id, "a node identity"),
            properties=self._properties(properties),
        )
        await self._client.run(query=query, context=context)

    async def get_node(
        self, *, context: SecurityContext, label: str, node_id: str
    ) -> dict[str, Any] | None:
        """Read one node's properties, or ``None`` when this tenant has no such node."""
        query = node_match(
            self._vocabulary.label(label),
            tenant=self._tenant(context),
            node_id=_require_id(node_id, "a node identity"),
        )
        return _node_of(await self._client.run(query=query, context=context))

    async def update_node(
        self,
        *,
        context: SecurityContext,
        label: str,
        node_id: str,
        properties: Mapping[str, object],
    ) -> bool:
        """Merge properties into one node; ``False`` means this tenant has no such node."""
        query = node_update(
            self._vocabulary.label(label),
            tenant=self._tenant(context),
            node_id=_require_id(node_id, "a node identity"),
            properties=self._properties(properties),
        )
        return bool(await self._client.run(query=query, context=context))

    async def delete_node(
        self, *, context: SecurityContext, label: str, node_id: str
    ) -> None:
        """Delete one node within the caller's tenant.

        Idempotent: a node that is already gone is not an error, so a retried delete cannot fail
        the operation that was already satisfied. The delete does not detach: a node that still
        has edges is refused by the database rather than quietly taking them with it.
        """
        query = node_delete(
            self._vocabulary.label(label),
            tenant=self._tenant(context),
            node_id=_require_id(node_id, "a node identity"),
        )
        await self._client.run(query=query, context=context)

    # -- Relationships ------------------------------------------------------

    async def relate(
        self,
        *,
        context: SecurityContext,
        relationship: str,
        from_label: str,
        from_id: str,
        to_label: str,
        to_id: str,
        properties: Mapping[str, object] | None = None,
    ) -> None:
        """Create an edge between two of this tenant's nodes.

        Both endpoints are matched under one tenant parameter, so an edge that would cross a
        tenant boundary has no endpoints to attach to. Creating the same edge twice is a no-op.
        """
        query = relationship_create(
            self._vocabulary.relationship_type(relationship),
            tenant=self._tenant(context),
            from_label=self._vocabulary.label(from_label),
            from_id=_require_id(from_id, "a node identity"),
            to_label=self._vocabulary.label(to_label),
            to_id=_require_id(to_id, "a node identity"),
            properties=self._properties(properties),
        )
        await self._client.run(query=query, context=context)

    async def related(
        self,
        *,
        context: SecurityContext,
        relationship: str,
        from_label: str,
        from_id: str,
        to_label: str,
        to_id: str,
    ) -> bool:
        """Answer whether this tenant has that edge."""
        query = relationship_match(
            self._vocabulary.relationship_type(relationship),
            tenant=self._tenant(context),
            from_label=self._vocabulary.label(from_label),
            from_id=_require_id(from_id, "a node identity"),
            to_label=self._vocabulary.label(to_label),
            to_id=_require_id(to_id, "a node identity"),
        )
        return _edge_of(await self._client.run(query=query, context=context)) is not None

    async def unrelate(
        self,
        *,
        context: SecurityContext,
        relationship: str,
        from_label: str,
        from_id: str,
        to_label: str,
        to_id: str,
    ) -> None:
        """Delete an edge within the caller's tenant. Idempotent, as the delete is."""
        query = relationship_delete(
            self._vocabulary.relationship_type(relationship),
            tenant=self._tenant(context),
            from_label=self._vocabulary.label(from_label),
            from_id=_require_id(from_id, "a node identity"),
            to_label=self._vocabulary.label(to_label),
            to_id=_require_id(to_id, "a node identity"),
        )
        await self._client.run(query=query, context=context)

    # -- Internals ----------------------------------------------------------

    def _tenant(self, context: SecurityContext) -> str:
        """The authoritative tenant: from the context, or the call fails closed."""
        return str(context.require_tenant().tenant_id)

    def _properties(
        self, properties: Mapping[str, object] | None
    ) -> dict[PropertyKey, object]:
        if not properties:
            return {}
        return {
            self._vocabulary.property_key(name): value for name, value in properties.items()
        }
