"""Layer 3 infrastructure: the gateway against a real Kong (directive §18, §19).

Skipped unless the Kong stack is running:

    bash tests/infra/kong/start.sh
    export JDLIB_INFRA_KONG_PROXY_URL=http://127.0.0.1:8000
    export JDLIB_INFRA_KONG_SECRET=<printed by the script>
    export JDLIB_INFRA_KONG_CLIENT_KEY=<printed by the script>
    pytest -q -W error -m infra

What is asserted through real Kong (kong:3.6, DB-less declarative config) and a
real upstream that reflects the forwarded request:

* routing: a request to the gateway reaches the upstream,
* authentication: Kong itself refuses a caller without a key (401),
* identity propagation: the gateway's assertion reaches the upstream,
* the assertion the upstream received actually verifies with the adapter,
* request ids: the gateway's correlation id reaches the upstream and differs
  per request,
* spoofed headers: a caller's own identity headers are replaced by the
  gateway's, so a forged subject cannot survive the hop,
* a forged validity window cannot survive either (the gateway sets it),
* invalid identity: a caller's forged secret never verifies,
* rate limiting: the configured limit produces 429 at the edge,
* direct access (bypassing the gateway): without the gateway's secret the
  adapter refuses the identity, so header claims are worthless off-gateway.
"""

from __future__ import annotations

import os
from datetime import timedelta

import httpx
import pytest
from pydantic import SecretStr

from jdlib.security.gateway.adapters import KongGatewayAdapter, NoGatewayAdapter
from jdlib.security.gateway.config import GatewayConfig, GatewayMode
from jdlib.security.interfaces import GatewayIdentity
from jdlib.tenancy.resolution import RequestInfo

PROXY_URL = os.environ.get("JDLIB_INFRA_KONG_PROXY_URL")
GATEWAY_SECRET = os.environ.get("JDLIB_INFRA_KONG_SECRET")
CLIENT_KEY = os.environ.get("JDLIB_INFRA_KONG_CLIENT_KEY")

pytestmark = [
    pytest.mark.infra,
    pytest.mark.skipif(
        not (PROXY_URL and GATEWAY_SECRET and CLIENT_KEY),
        reason="set JDLIB_INFRA_KONG_PROXY_URL/_SECRET/_CLIENT_KEY (see tests/infra/kong/start.sh)",
    ),
]

DOCUMENTS_PATH = "/documents/42"


@pytest.fixture
def adapter() -> KongGatewayAdapter:
    assert GATEWAY_SECRET is not None
    config = GatewayConfig(mode=GatewayMode.SHARED_SECRET, secret=SecretStr(GATEWAY_SECRET))
    return KongGatewayAdapter(config=config)


def _request_info(payload: dict[str, object], *, path: str = DOCUMENTS_PATH) -> RequestInfo:
    headers = payload.get("headers")
    assert isinstance(headers, dict)
    return RequestInfo(
        headers={key.lower(): str(value) for key, value in headers.items()},
        query={},
        path=path,
        host="api.internal",
    )


async def _through_gateway(
    *, path: str = DOCUMENTS_PATH, **headers: str | None
) -> httpx.Response:
    assert PROXY_URL is not None and CLIENT_KEY is not None
    request_headers = {"apikey": CLIENT_KEY}
    request_headers.update({key: value for key, value in headers.items() if value is not None})
    async with httpx.AsyncClient() as client:
        return await client.get(f"{PROXY_URL}{path}", headers=request_headers, timeout=10)


# --- routing and authentication ----------------------------------------------


async def test_gateway_routes_to_the_upstream() -> None:
    response = await _through_gateway()
    assert response.status_code == 200
    body = response.json()
    assert body["path"] == DOCUMENTS_PATH
    assert body["headers"]["host"] == "jdlib-echo:8080"


async def test_gateway_authentication_is_enforced_at_the_edge() -> None:
    assert PROXY_URL is not None
    async with httpx.AsyncClient() as client:
        without_key = await client.get(f"{PROXY_URL}{DOCUMENTS_PATH}", timeout=10)
        with_wrong_key = await client.get(
            f"{PROXY_URL}{DOCUMENTS_PATH}", headers={"apikey": "not-a-key"}, timeout=10
        )
    assert without_key.status_code == 401
    assert with_wrong_key.status_code == 401
    assert "API key" in without_key.json()["message"]
    assert with_wrong_key.json()["message"] == "Unauthorized"


# --- identity propagation and verification -----------------------------------


async def test_gateway_identity_reaches_the_upstream_and_verifies(
    adapter: KongGatewayAdapter,
) -> None:
    response = await _through_gateway()
    headers = response.json()["headers"]
    assert headers["x-jdlib-subject"] == "acme-service"
    assert headers["x-jdlib-tenant"] == "acme"
    assert "x-jdlib-gateway-secret" in headers

    identity = await adapter.verify_identity(_request_info(response.json()))
    assert isinstance(identity, GatewayIdentity)
    assert identity.subject == "acme-service"
    assert identity.tenant_slug == "acme"
    assert identity.scopes == frozenset({"documents:read", "documents:write"})


async def test_request_ids_are_propagated_and_unique() -> None:
    first = await _through_gateway()
    second = await _through_gateway()
    first_id = first.json()["headers"].get("x-request-id")
    second_id = second.json()["headers"].get("x-request-id")
    assert first_id and second_id
    assert first_id != second_id
    assert first.headers.get("x-request-id") == first_id


# --- spoofing ----------------------------------------------------------------


async def test_caller_identity_headers_are_replaced_not_appended(
    adapter: KongGatewayAdapter,
) -> None:
    response = await _through_gateway(
        **{
            "x-jdlib-subject": "admin",
            "x-jdlib-tenant": "other-tenant",
            "x-jdlib-scopes": "tenants:admin",
            "x-jdlib-gateway-secret": "forged-secret-forged-secret-forged-secret",
        }
    )
    headers = response.json()["headers"]
    # the gateway's values won: one value, not a smuggled second one
    assert headers["x-jdlib-subject"] == "acme-service"
    assert headers["x-jdlib-tenant"] == "acme"
    assert headers["x-jdlib-scopes"] == "documents:read documents:write"
    assert headers["x-jdlib-gateway-secret"] != "forged-secret-forged-secret-forged-secret"

    identity = await adapter.verify_identity(_request_info(response.json()))
    assert identity is not None
    assert identity.subject == "acme-service"
    assert identity.tenant_slug == "acme"
    assert "tenants:admin" not in identity.scopes


async def test_a_forged_validity_window_cannot_survive_the_gateway(
    adapter: KongGatewayAdapter,
) -> None:
    response = await _through_gateway(
        **{
            "x-jdlib-issued-at": "0",
            "x-jdlib-expires-at": "4102444800",  # year 2100: a window an adapter must refuse
        }
    )
    headers = response.json()["headers"]
    assert headers["x-jdlib-issued-at"] != "0"
    assert headers["x-jdlib-expires-at"] != "4102444800"
    identity = await adapter.verify_identity(_request_info(response.json()))
    assert identity is not None  # the gateway's fresh window replaced the forgery


# --- invalid identity and direct access --------------------------------------


async def test_off_gateway_identity_claims_are_worthless() -> None:
    # Simulates a caller talking to the backend directly with identity headers:
    # the shared-secret adapter refuses (no gateway secret) and the NONE-mode
    # adapter ignores headers outright.
    forged = RequestInfo(
        headers={
            "x-jdlib-subject": "admin",
            "x-jdlib-tenant": "acme",
            "x-jdlib-scopes": "tenants:admin",
            "x-jdlib-issued-at": "1",
            "x-jdlib-expires-at": "4102444800",
        },
        query={},
        path=DOCUMENTS_PATH,
        host="backend.internal",
    )
    assert await NoGatewayAdapter().verify_identity(forged) is None
    assert GATEWAY_SECRET is not None
    strict = KongGatewayAdapter(
        config=GatewayConfig(mode=GatewayMode.SHARED_SECRET, secret=SecretStr(GATEWAY_SECRET)),
        clock=None,
    )
    assert await strict.verify_identity(forged) is None


# --- rate limiting -----------------------------------------------------------


async def test_rate_limiting_is_enforced_at_the_edge() -> None:
    assert PROXY_URL is not None and CLIENT_KEY is not None
    statuses: list[int] = []
    async with httpx.AsyncClient() as client:
        for _ in range(12):
            response = await client.get(
                f"{PROXY_URL}/limited/42", headers={"apikey": CLIENT_KEY}, timeout=10
            )
            statuses.append(response.status_code)
    assert 429 in statuses, f"expected the configured limit to trigger: {statuses}"
    limited = statuses.index(429)
    assert all(status == 200 for status in statuses[:limited])


def test_gateway_window_is_within_the_configured_skew(adapter: KongGatewayAdapter) -> None:
    # the gateway sets issued=now-5/expires=now+55, so a 60s skew is enough
    assert adapter.config.max_skew == timedelta(seconds=60)
