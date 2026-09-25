"""Read-only resources, and the rule that governs their payloads (directive §23).

§23 asks for read-only resources — tenant, graph, schema, health — and states the rule that
matters in one line: *never expose internal secrets/configuration*. A resource is a body a client
reads without asking for anything, so the failure mode is not a refusal that went wrong but a
field that should never have been in the body. Three consequences shape this module:

* the tenant resource describes **the caller's own tenant**, read from the ambient context. There
  is no argument to name a tenant with, and the context is the only source, so a cross-tenant
  read is not expressible rather than merely refused;
* no payload carries authority. A privilege is a capability the caller holds, not a description
  of them; it stays out of every body, and `sensitive` marks the ones whose *reading* is the
  auditable event rather than whose content is secret;
* health says the surface is alive and nothing else. No versions, no component list, no
  configuration — a health resource that describes the deployment is a reconnaissance endpoint
  with a reassuring name.

Resources take no arguments at all: that is what makes them resources rather than tools, and it is
why a resource handler cannot be handed an identity even in principle.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from jdlib.graph.models import GraphVocabulary
from jdlib.integrations.mcp.errors import McpResourceDefinitionError
from jdlib.security.context import current_security_context

#: Reading a description of one's own tenancy.
TENANT_CAPABILITY = "tenant:read"

#: Reading the graph's declared vocabulary — the same capability the graph read tools require.
GRAPH_CAPABILITY = "graph:read"

#: Reading liveness.
HEALTH_CAPABILITY = "health:read"

_URI_PREFIX = "jdlib://"


@dataclass(frozen=True, slots=True)
class McpResource:
    """A read-only resource: a URI, what it requires, and what it answers.

    A resource that declares no capability cannot be constructed, for the same reason a tool
    cannot: §23's "authorized" is not a property a reviewer adds later.
    """

    uri: str
    name: str
    description: str
    handler: Callable[[], Awaitable[Any]]
    capability: str
    sensitive: bool = False
    mime_type: str = "application/json"

    def __post_init__(self) -> None:
        if not self.uri.startswith(_URI_PREFIX) or len(self.uri) <= len(_URI_PREFIX):
            raise McpResourceDefinitionError("a resource URI is a jdlib:// path")
        if not self.name.strip():
            raise McpResourceDefinitionError("a resource has a name")
        if not self.description.strip():
            raise McpResourceDefinitionError("a resource describes itself")
        if not callable(self.handler):
            raise McpResourceDefinitionError("a resource has a handler")
        if not self.capability:
            raise McpResourceDefinitionError(
                f"{self.uri} declares no capability; a resource is not implicitly public"
            )


def tenant_resource() -> McpResource:
    """The caller's own tenancy, described from the ambient context and nowhere else."""

    async def handler() -> dict[str, Any]:
        tenant = current_security_context().require_tenant()
        return {
            "tenant_id": str(tenant.tenant_id),
            "tenant_slug": tenant.tenant_slug,
            "principal_id": str(tenant.principal.id),
            "principal_kind": str(tenant.principal.kind),
            "request_id": tenant.request_id,
        }

    return McpResource(
        uri="jdlib://tenant",
        name="tenant",
        description="The authenticated caller's own tenant and principal.",
        handler=handler,
        capability=TENANT_CAPABILITY,
        sensitive=True,
    )


def graph_schema_resource(vocabulary: GraphVocabulary) -> McpResource:
    """The graph's declared vocabulary — a contract, not a configuration.

    Sorted, so two reads of the same deployment answer the same bytes.
    """

    async def handler() -> dict[str, Any]:
        return {
            "labels": sorted(vocabulary.labels),
            "relationship_types": sorted(vocabulary.relationship_types),
            "property_keys": sorted(vocabulary.property_keys),
        }

    return McpResource(
        uri="jdlib://graph/schema",
        name="graph-schema",
        description="The labels, relationship types and property keys this deployment declares.",
        handler=handler,
        capability=GRAPH_CAPABILITY,
    )


def health_resource() -> McpResource:
    """Liveness, and nothing else.

    Deliberately empty of detail: no version, no dependency, no configuration. A health surface
    that describes the deployment is reconnaissance with a reassuring name, and the application's
    own readiness endpoint is where an operator's diagnostics belong.
    """

    async def handler() -> dict[str, Any]:
        return {"status": "ok"}

    return McpResource(
        uri="jdlib://health",
        name="health",
        description="Whether this surface is serving.",
        handler=handler,
        capability=HEALTH_CAPABILITY,
    )
