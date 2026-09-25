"""Read-only resources: what they may say, and what they may never say (directive §23).

§23 asks for read-only resources — tenant, graph, schema, health — and states the rules in one
line: *never expose internal secrets/configuration*. This module pins the payloads themselves,
because a resource is a thing a client reads without asking, and the failure mode is not a
refusal that went wrong but a field that should never have been in the body:

* the tenant resource describes **the caller's own tenant** and nothing else — the ambient
  context is the only source, so a second context produces a second answer and no cross-tenant
  read is expressible;
* no payload carries a secret, a connection string, a credential or a privilege: the tests walk
  every resource's body for keys that would mean one, and `privilege` is excluded by name
  because authority is not a display value;
* health says that the surface is alive and nothing else — no versions, no component list, no
  configuration, since a health endpoint that describes the deployment is a reconnaissance
  endpoint with a reassuring name;
* every resource declares a capability and none is public: §23's "authorized" applies to reading
  as much as §20's does to doing.

Resources take no arguments — that is what makes them resources rather than tools — so a resource
handler cannot be handed an identity even in principle.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import uuid
from typing import Any

import pytest

from jdlib.errors import AuthenticationError
from jdlib.graph.models import GraphVocabulary
from jdlib.integrations.mcp.errors import McpResourceDefinitionError
from jdlib.integrations.mcp.resources import (
    McpResource,
    graph_schema_resource,
    health_resource,
    tenant_resource,
)
from jdlib.security.context import security_context_scope
from tests.support.graph_fakes import graph_context

TENANT_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")

#: Key fragments that mean "this payload is describing something it should not".
FORBIDDEN_FRAGMENTS = (
    "secret",
    "password",
    "passwd",
    "credential",
    "token",
    "api_key",
    "apikey",
    "private",
    "dsn",
    "connection",
    "conn_str",
    "url",
    "uri",
    "host",
    "port",
    "dsn",
    "config",
    "privilege",
    "privileges",
)


def _vocabulary() -> GraphVocabulary:
    return GraphVocabulary(
        labels=frozenset({"User", "Post"}),
        relationship_types=frozenset({"FOLLOWS"}),
        property_keys=frozenset({"name"}),
    )


def _all_resources() -> tuple[McpResource, ...]:
    return (tenant_resource(), graph_schema_resource(_vocabulary()), health_resource())


def _flatten(payload: Any, prefix: str = "") -> list[str]:
    keys: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            keys.append(f"{prefix}{key}")
            keys.extend(_flatten(value, f"{prefix}{key}."))
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            keys.extend(_flatten(item, prefix))
    return keys


async def test_every_resource_declares_a_capability_and_none_is_public() -> None:
    for resource in _all_resources():
        assert resource.capability, f"{resource.uri} declares no capability"
        assert resource.uri.startswith("jdlib://")
        assert resource.name
        assert resource.description.strip()


async def test_no_resource_payload_names_something_internal() -> None:
    """Walk every body: a key that would mean a secret, a DSN or a privilege fails the suite."""
    with security_context_scope(graph_context(tenant_id=TENANT_ID)):
        for resource in _all_resources():
            payload = await resource.handler()
            for key in _flatten(payload):
                lowered = key.lower()
                for fragment in FORBIDDEN_FRAGMENTS:
                    assert fragment not in lowered, f"{resource.uri} exposes {key}"


async def test_the_tenant_resource_describes_the_callers_own_tenant() -> None:
    other = uuid.UUID("44444444-4444-4444-4444-444444444444")
    with security_context_scope(graph_context(tenant_id=TENANT_ID)):
        mine = await tenant_resource().handler()
    with security_context_scope(graph_context(tenant_id=other)):
        theirs = await tenant_resource().handler()
    assert mine["tenant_id"] == str(TENANT_ID)
    assert theirs["tenant_id"] == str(other)
    assert mine != theirs


async def test_the_tenant_resource_does_not_carry_authority() -> None:
    """A privilege is authority, not a description; the payload never includes one."""
    with security_context_scope(graph_context(tenant_id=TENANT_ID)):
        payload = await tenant_resource().handler()
    assert "privilege" not in payload
    assert set(payload) <= {
        "tenant_id",
        "tenant_slug",
        "principal_id",
        "principal_kind",
        "request_id",
    }


async def test_health_says_only_that_the_surface_is_alive() -> None:
    payload = await health_resource().handler()
    assert payload == {"status": "ok"}


async def test_the_schema_resource_reports_the_declared_vocabulary_deterministically() -> None:
    payload = await graph_schema_resource(_vocabulary()).handler()
    assert payload == {
        "labels": ["Post", "User"],
        "relationship_types": ["FOLLOWS"],
        "property_keys": ["name"],
    }


async def test_the_schema_resource_answers_the_same_bytes_in_a_second_process() -> None:
    """Determinism is a claim about processes, not about one run.

    A frozenset's iteration order depends on the hash seed, so an unsorted payload varies
    between two processes reading the same deployment. Only a second process can see that;
    in-process, the order can coincide with sorted order and hide it.
    """
    root = repr(str(pathlib.Path(__file__).resolve().parents[2]))
    script = (
        "import asyncio, json, sys;"
        "sys.path.insert(0, " + root + ");"
        "from jdlib.graph.models import GraphVocabulary;"
        "from jdlib.integrations.mcp.resources import graph_schema_resource;"
        "v = GraphVocabulary(labels=frozenset({'User', 'Post', 'Audit'}),"
        " relationship_types=frozenset({'FOLLOWS', 'MENTIONS', 'BLOCKS'}),"
        " property_keys=frozenset({'name', 'age', 'created_at'}));"
        "print(json.dumps(asyncio.run(graph_schema_resource(v).handler()), sort_keys=True))"
    )
    outputs = set()
    for seed in ("0", "1", "12345"):
        env = {
            **os.environ,
            "PYTHONPATH": str(pathlib.Path(__file__).resolve().parents[2]),
            "PYTHONHASHSEED": seed,
        }
        r = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, env=env, timeout=120
        )
        assert r.returncode == 0, r.stderr[-400:]
        outputs.add(r.stdout.strip())
    assert len(outputs) == 1, f"the payload varies between processes: {outputs}"


async def test_a_resource_without_a_context_is_refused_rather_than_guessed() -> None:
    with pytest.raises(AuthenticationError):
        await tenant_resource().handler()


async def test_a_resource_with_no_capability_cannot_be_constructed() -> None:
    """§23's "authorized" is not a property a reviewer adds later."""

    async def handler() -> dict[str, Any]:
        return {}

    with pytest.raises(McpResourceDefinitionError):
        McpResource(
            uri="jdlib://anything",
            name="anything",
            description="Anything.",
            handler=handler,
            capability="",
        )


async def test_a_resource_takes_no_arguments() -> None:
    """No parameters is what makes it a resource; the test keeps it that way."""
    import inspect

    for resource in _all_resources():
        signature = inspect.signature(resource.handler)
        assert not signature.parameters, f"{resource.uri} accepts arguments"
