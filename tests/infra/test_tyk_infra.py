"""Layer 3 infrastructure: the gateway against a real Tyk (directive §18, §19).

Skipped unless the Tyk stack is running:

    bash tests/infra/tyk/start.sh
    set -a; . tests/infra/out/tyk-credentials.env; set +a
    export JDLIB_INFRA_TYK_URL=http://127.0.0.1:8081
    pytest -q -W error -m infra

Same properties as the Kong suite, asserted through Tyk and its own header
conventions (``x-tyk-jdlib-*``, which is exactly what
:class:`TykGatewayAdapter` expects by default):

* routing, edge authentication (401 without a key), identity propagation,
* the propagated assertion verifies with the adapter,
* a caller's own identity headers cannot survive the hop,
* a forged validity window cannot survive either — Tyk's middleware stamps a
  fresh one per request,
* off-gateway identity claims are worthless.
"""

from __future__ import annotations

import os

import httpx
import pytest
from pydantic import SecretStr

from jdlib.security.gateway.adapters import NoGatewayAdapter, TykGatewayAdapter
from jdlib.security.gateway.config import GatewayConfig, GatewayMode
from jdlib.security.interfaces import GatewayIdentity
from jdlib.tenancy.resolution import RequestInfo

GATEWAY_URL = os.environ.get("JDLIB_INFRA_TYK_URL")
GATEWAY_SECRET = os.environ.get("JDLIB_INFRA_TYK_SECRET")
API_KEY = os.environ.get("JDLIB_INFRA_TYK_API_KEY")

pytestmark = [
    pytest.mark.infra,
    pytest.mark.skipif(
        not (GATEWAY_URL and GATEWAY_SECRET and API_KEY),
        reason="set JDLIB_INFRA_TYK_URL/_SECRET/_API_KEY (see tests/infra/tyk/start.sh)",
    ),
]

DOCUMENTS_PATH = "/documents/42"


@pytest.fixture
def adapter() -> TykGatewayAdapter:
    assert GATEWAY_SECRET is not None
    config = GatewayConfig(mode=GatewayMode.SHARED_SECRET, secret=SecretStr(GATEWAY_SECRET))
    return TykGatewayAdapter(config=config)


def _request_info(payload: dict[str, object], *, path: str = DOCUMENTS_PATH) -> RequestInfo:
    headers = payload.get("headers")
    assert isinstance(headers, dict)
    return RequestInfo(
        headers={key.lower(): str(value) for key, value in headers.items()},
        query={},
        path=path,
        host="api.internal",
    )


async def _through_gateway(*, path: str = DOCUMENTS_PATH, **headers: str | None) -> httpx.Response:
    assert GATEWAY_URL is not None and API_KEY is not None
    request_headers = {"apikey": API_KEY}
    request_headers.update({key: value for key, value in headers.items() if value is not None})
    async with httpx.AsyncClient() as client:
        return await client.get(f"{GATEWAY_URL}{path}", headers=request_headers, timeout=10)


async def test_gateway_routes_to_the_upstream() -> None:
    response = await _through_gateway()
    assert response.status_code == 200
    assert response.json()["path"] == DOCUMENTS_PATH


async def test_gateway_authentication_is_enforced_at_the_edge() -> None:
    assert GATEWAY_URL is not None
    async with httpx.AsyncClient() as client:
        without_key = await client.get(f"{GATEWAY_URL}{DOCUMENTS_PATH}", timeout=10)
        with_wrong_key = await client.get(
            f"{GATEWAY_URL}{DOCUMENTS_PATH}", headers={"apikey": "not-a-key"}, timeout=10
        )
    assert without_key.status_code in {401, 403}
    assert with_wrong_key.status_code in {401, 403}


async def test_gateway_identity_reaches_the_upstream_and_verifies(
    adapter: TykGatewayAdapter,
) -> None:
    response = await _through_gateway()
    headers = response.json()["headers"]
    assert headers["x-tyk-jdlib-subject"] == "acme-service"
    assert headers["x-tyk-jdlib-tenant"] == "acme"
    assert headers["x-tyk-jdlib-issued-at"]
    assert headers["x-tyk-jdlib-expires-at"]

    identity = await adapter.verify_identity(_request_info(response.json()))
    assert isinstance(identity, GatewayIdentity)
    assert identity.subject == "acme-service"
    assert identity.tenant_slug == "acme"
    assert identity.scopes == frozenset({"documents:read", "documents:write"})


async def test_caller_identity_headers_do_not_win(adapter: TykGatewayAdapter) -> None:
    response = await _through_gateway(
        **{
            "x-tyk-jdlib-subject": "admin",
            "x-tyk-jdlib-tenant": "other-tenant",
            "x-tyk-jdlib-scopes": "tenants:admin",
            "x-tyk-jdlib-gateway-secret": "forged-secret-forged-secret-forged-secret",
        }
    )
    identity = await adapter.verify_identity(_request_info(response.json()))
    assert identity is not None
    assert identity.subject == "acme-service"
    assert identity.tenant_slug == "acme"
    assert "tenants:admin" not in identity.scopes


async def test_a_forged_validity_window_cannot_survive_the_gateway(
    adapter: TykGatewayAdapter,
) -> None:
    response = await _through_gateway(
        **{"x-tyk-jdlib-issued-at": "0", "x-tyk-jdlib-expires-at": "4102444800"}
    )
    identity = await adapter.verify_identity(_request_info(response.json()))
    assert identity is not None
    assert identity.expires_at.year < 2100


async def test_off_gateway_identity_claims_are_worthless() -> None:
    forged = RequestInfo(
        headers={
            "x-tyk-jdlib-subject": "admin",
            "x-tyk-jdlib-tenant": "acme",
            "x-tyk-jdlib-scopes": "tenants:admin",
            "x-tyk-jdlib-issued-at": "1",
            "x-tyk-jdlib-expires-at": "4102444800",
        },
        query={},
        path=DOCUMENTS_PATH,
        host="backend.internal",
    )
    assert await NoGatewayAdapter().verify_identity(forged) is None
    assert GATEWAY_SECRET is not None
    strict = TykGatewayAdapter(
        config=GatewayConfig(mode=GatewayMode.SHARED_SECRET, secret=SecretStr(GATEWAY_SECRET))
    )
    assert await strict.verify_identity(forged) is None
