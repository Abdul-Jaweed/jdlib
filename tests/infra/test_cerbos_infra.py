"""Layer 3 infrastructure: the Cerbos adapter against a real Cerbos (directive §16).

Skipped unless ``JDLIB_INFRA_CERBOS_URL`` points at a running Cerbos:

    docker compose -f tests/infra/docker-compose.yml up -d cerbos
    export JDLIB_INFRA_CERBOS_URL=http://localhost:3592

Real policies (``tests/infra/cerbos/policies``) are loaded by the engine, and
the real HTTP transport is used, so these tests prove the request shape and the
response mapping against the actual wire protocol rather than a fixture.

The critical property (directive §16) is asserted here over real infrastructure:
when Cerbos is unavailable, times out, or has no policy for the resource, the
decision is NOT ALLOW.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import timedelta

import httpx
import pytest

from jdlib.security.authz.cerbos import CerbosConfig, CerbosPDP
from jdlib.security.authz.decision import AuthorizationQuery
from jdlib.security.authz.transports import HttpCerbosTransport

CERBOS_URL = os.environ.get("JDLIB_INFRA_CERBOS_URL")

pytestmark = [
    pytest.mark.infra,
    pytest.mark.skipif(
        not CERBOS_URL, reason="set JDLIB_INFRA_CERBOS_URL to run against real Cerbos"
    ),
]

TENANT_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
OTHER_TENANT_ID = uuid.UUID("99999999-8888-7777-6666-555555555555")
PRINCIPAL_ID = "user-1"
OWNER_ATTRIBUTES = {"tenantId": str(TENANT_ID), "ownerId": PRINCIPAL_ID, "department": "editorial"}


def _pdp(endpoint: str | None = None, *, timeout: timedelta | None = None) -> CerbosPDP:
    url = endpoint or CERBOS_URL
    assert url is not None
    config = CerbosConfig(
        endpoint=url, timeout=timeout or timedelta(seconds=5)
    )
    return CerbosPDP(config=config, transport=HttpCerbosTransport(timeout=config.timeout))


def _query(
    *,
    action: str = "view",
    roles: frozenset[str] = frozenset({"editor"}),
    tenant_id: uuid.UUID = TENANT_ID,
    resource_kind: str = "document",
    resource_id: str = "doc-42",
    attributes: dict[str, object] | None = None,
    principal_id: str = PRINCIPAL_ID,
) -> AuthorizationQuery:
    return AuthorizationQuery(
        principal_id=principal_id,
        tenant_id=tenant_id,
        resource_kind=resource_kind,
        resource_id=resource_id,
        actions=(action,),
        roles=roles,
        attributes=OWNER_ATTRIBUTES if attributes is None else attributes,
    )


async def test_real_cerbos_is_reachable_and_healthy() -> None:
    assert CERBOS_URL is not None
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{CERBOS_URL}/_cerbos/health", timeout=10)
    assert response.status_code == 200


# --- decisions ---------------------------------------------------------------


async def test_allow_from_a_real_policy() -> None:
    decision = await _pdp().decide(_query(action="view"))
    assert decision.allowed is True
    assert decision.degraded is False
    # Cerbos reports the fully qualified policy name, which carries the version.
    assert decision.policy_id is not None
    assert decision.policy_id.startswith("resource.document")
    assert "vdefault" in decision.policy_id


async def test_owner_can_edit_but_a_non_owner_cannot() -> None:
    owner = await _pdp().decide(_query(action="edit"))
    assert owner.allowed is True
    other = await _pdp().decide(_query(action="edit", principal_id="user-2"))
    assert other.allowed is False
    assert other.denied_actions == ("edit",)


async def test_deny_for_the_wrong_action() -> None:
    decision = await _pdp().decide(_query(action="destroy"))
    assert decision.allowed is False
    assert decision.degraded is False  # a policy decision, not an engine failure


async def test_deny_for_the_wrong_principal_role() -> None:
    decision = await _pdp().decide(_query(action="delete", roles=frozenset({"viewer"})))
    assert decision.allowed is False
    admin = await _pdp().decide(_query(action="delete", roles=frozenset({"admin"})))
    assert admin.allowed is True


async def test_deny_for_the_wrong_tenant() -> None:
    decision = await _pdp().decide(
        _query(action="view", tenant_id=OTHER_TENANT_ID, attributes=OWNER_ATTRIBUTES)
    )
    assert decision.allowed is False
    # even an admin from another tenant is refused
    admin = await _pdp().decide(
        _query(action="delete", roles=frozenset({"admin"}), tenant_id=OTHER_TENANT_ID)
    )
    assert admin.allowed is False


async def test_deny_for_a_missing_attribute() -> None:
    # 'publish' requires department == editorial; without the attribute it denies.
    decision = await _pdp().decide(
        _query(action="publish", attributes={"tenantId": str(TENANT_ID), "ownerId": PRINCIPAL_ID})
    )
    assert decision.allowed is False
    allowed = await _pdp().decide(_query(action="publish"))
    assert allowed.allowed is True


async def test_unknown_resource_is_denied_with_no_match_metadata() -> None:
    # Cerbos answers a resource with no matching policy with EFFECT_DENY and
    # matchedPolicy "NO_MATCH" - a decision, not an engine failure.
    decision = await _pdp().decide(_query(resource_kind="unpolicied-resource"))
    assert decision.allowed is False
    assert decision.degraded is False
    assert decision.policy_id == "NO_MATCH"


async def test_all_actions_must_be_allowed_on_a_real_engine() -> None:
    query = AuthorizationQuery(
        principal_id=PRINCIPAL_ID,
        tenant_id=TENANT_ID,
        resource_kind="document",
        resource_id="doc-42",
        actions=("view", "delete"),
        roles=frozenset({"editor"}),
        attributes=OWNER_ATTRIBUTES,
    )
    decision = await _pdp().decide(query)
    assert decision.allowed is False
    assert decision.denied_actions == ("delete",)


# --- fail closed over real infrastructure ------------------------------------


async def test_unavailable_cerbos_never_allows() -> None:
    # nothing is listening on this port: a genuine connection failure
    decision = await _pdp("http://127.0.0.1:59999", timeout=timedelta(seconds=1)).decide(_query())
    assert decision.allowed is False
    assert decision.degraded is True
    assert decision.reason == "engine_unavailable"


async def test_timing_out_cerbos_never_allows() -> None:
    decision = await _pdp(timeout=timedelta(microseconds=1)).decide(_query())
    assert decision.allowed is False
    assert decision.degraded is True
    assert decision.reason == "engine_unavailable"


async def test_denied_decisions_expose_only_safe_metadata() -> None:
    decision = await _pdp().decide(_query(action="destroy"))
    metadata = decision.safe_metadata()
    serialized = json.dumps(metadata)
    assert set(metadata) == {"decision", "policy_id", "policy_version", "decided_at", "reason"}
    assert "editorial" not in serialized
    assert PRINCIPAL_ID not in serialized
    assert str(TENANT_ID) not in serialized
    assert metadata["decision"] == "DENY"
