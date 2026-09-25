"""The live half: a real policy engine answers the query this application builds.

The static half lives beside the policies (`config/cerbos/policies/tenant_scope_test.yaml`,
executed by `cerbos compile`). This file proves the other half -- that the query `query_for` builds
is the one the engine receives, and that its answer is the one the policies promise, including the
cross-tenant denial.

Bring the engine up with the documented command, then run this file:

    export JDLIB_ENTERPRISE_POSTGRES_PASSWORD="$(python -c 'import secrets; \
        print(secrets.token_urlsafe(24))')"
    docker compose -f examples/enterprise/docker/docker-compose.yml up -d cerbos
    export JDLIB_EXAMPLE_CERBOS_ENDPOINT=http://127.0.0.1:4592
    pytest examples/enterprise/tests/test_authorization_live.py -q -W error

With the endpoint unset the whole file skips with that reason rather than failing: a missing lab
belongs in the summary as a skip, not as a red suite.
"""

from __future__ import annotations

import os
import uuid
from datetime import timedelta

import pytest

from examples.enterprise.app.security.authorization import query_for
from jdlib.authz.scopes import ScopeRef
from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy, ScopeType
from jdlib.security.authz import CerbosConfig, CerbosPDP
from jdlib.security.authz.decision import AuthorizationDecision, AuthorizationQuery
from jdlib.security.authz.transports import HttpCerbosTransport

ENDPOINT = os.environ.get("JDLIB_EXAMPLE_CERBOS_ENDPOINT", "")

pytestmark = pytest.mark.skipif(
    not ENDPOINT,
    reason=(
        "the example's policy engine is not running: docker compose -f "
        "examples/enterprise/docker/docker-compose.yml up -d cerbos, then export "
        "JDLIB_EXAMPLE_CERBOS_ENDPOINT=http://127.0.0.1:4592"
    ),
)

TENANT_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
PRINCIPAL_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _context(*, tenant_id: uuid.UUID = TENANT_A) -> TenantContext:
    return TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=Principal(kind=PrincipalKind.USER, id=PRINCIPAL_ID, tenant_id=tenant_id),
        request_id="req-live-1",
        correlation_id="corr-live-1",
    )


def _pdp() -> CerbosPDP:
    return CerbosPDP(
        config=CerbosConfig(endpoint=ENDPOINT),
        transport=HttpCerbosTransport(timeout=timedelta(seconds=5)),
    )


async def _decide(
    permission: str, *, roles: set[str], tenant_id: uuid.UUID = TENANT_A
) -> AuthorizationDecision:
    query = query_for(
        permission,
        ScopeRef(type=ScopeType.TENANT, id=None),
        context=_context(tenant_id=tenant_id),
        roles=frozenset(roles),
    )
    return await _pdp().decide(query)


async def test_a_role_the_policy_names_is_allowed_its_actions() -> None:
    for permission in ("tenant:read", "audit:read"):
        decision = await _decide(permission, roles={"admin"})
        assert decision.allowed is True, f"{permission}: {decision.reason}"
        assert decision.degraded is False


async def test_a_role_the_policy_does_not_name_is_denied() -> None:
    decision = await _decide("tenant:read", roles={"viewer"})
    assert decision.allowed is False
    assert decision.degraded is False


async def test_the_lifecycle_actions_belong_to_the_administrator() -> None:
    assert (await _decide("tenant:suspend", roles={"admin"})).allowed is True
    assert (await _decide("tenant:suspend", roles={"support"})).allowed is False
    assert (await _decide("data:export", roles={"support"})).allowed is False


async def test_an_administrator_of_another_tenant_is_denied() -> None:
    """The property the mapping exists for, answered by the engine rather than by a stub.

    The query here is built by hand with the principal's tenant differing from the resource's --
    `query_for` cannot produce it (a route has no argument for a tenant), so this is what a caller
    reaching past the bridge would have to write. The policy denies it on its own rule, which is the
    second, independent check.
    """
    query = AuthorizationQuery(
        principal_id=str(PRINCIPAL_ID),
        tenant_id=TENANT_A,
        resource_kind="scope",
        resource_id=ScopeType.TENANT.value,
        actions=("tenant:read",),
        roles=frozenset({"admin"}),
        attributes={"tenantId": str(TENANT_A)},
        principal_attributes={"tenantId": str(TENANT_B)},
    )
    decision = await _pdp().decide(query)
    assert decision.allowed is False
    assert decision.degraded is False
