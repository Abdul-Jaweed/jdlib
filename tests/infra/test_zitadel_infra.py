"""Layer 3 infrastructure: the authentication adapters against a real ZITADEL.

Skipped unless ``JDLIB_INFRA_ZITADEL_ISSUER`` points at a running ZITADEL
(directive §12). Start it with:

    docker compose -f tests/infra/docker-compose.yml up -d zitadel
    export JDLIB_INFRA_ZITADEL_ISSUER=http://127.0.0.1:8080

The hermetic layer (``tests/integration/test_authn_http_integration.py``)
already covers behaviour over real HTTP; what this layer adds is vendor
fidelity: the real discovery paths (``/oauth/v2/keys``), real key material and
real error responses. It asserts that the *generic* objects produced by
``ZitadelConfig`` behave correctly against the live service.
"""

from __future__ import annotations

import os
from datetime import timedelta

import httpx
import pytest

from jdlib.authn.oidc import JwksCache
from jdlib.errors import JdlibError
from jdlib.security.authn.jwt import JwtClaimMapping, JwtTokenValidator
from jdlib.security.authn.transports import HttpJwksFetcher
from jdlib.security.authn.zitadel import (
    ZitadelConfig,
    build_zitadel_token_validator,
)

ISSUER = os.environ.get("JDLIB_INFRA_ZITADEL_ISSUER")

pytestmark = [
    pytest.mark.infra,
    pytest.mark.skipif(
        not ISSUER, reason="set JDLIB_INFRA_ZITADEL_ISSUER to run against real ZITADEL"
    ),
]


async def test_real_jwks_endpoint_is_fetchable_and_parsable() -> None:
    """The derived JWKS URI is the one a real ZITADEL serves."""
    assert ISSUER is not None
    config = ZitadelConfig(issuer=ISSUER, audience="jdlib-api")
    assert config.resolved_jwks_uri() == f"{ISSUER}/oauth/v2/keys"

    async with httpx.AsyncClient() as client:
        response = await client.get(config.resolved_jwks_uri(), timeout=10)
    assert response.status_code == 200
    document = response.json()
    assert isinstance(document.get("keys"), list)
    for jwk in document["keys"]:
        assert jwk.get("kid")
        assert jwk.get("kty") in {"RSA", "EC"}


async def test_validator_loads_real_key_material_from_zitadel() -> None:
    assert ISSUER is not None
    config = ZitadelConfig(issuer=ISSUER, audience="jdlib-api")
    validator = build_zitadel_token_validator(
        config, fetch=HttpJwksFetcher(url=config.resolved_jwks_uri())
    )
    cache = validator.keys
    assert isinstance(cache, JwksCache)
    await cache.ready()  # no key material yet
    # an unsigned/garbage token must fail closed against real key material
    with pytest.raises(JdlibError):
        await validator.validate("not-a-jwt")


async def test_real_discovery_document_matches_derived_endpoints() -> None:
    """The endpoints we derive must be the ones ZITADEL advertises."""
    assert ISSUER is not None
    config = ZitadelConfig(issuer=ISSUER, audience="jdlib-api")
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{ISSUER}/.well-known/openid-configuration", timeout=10)
    assert response.status_code == 200
    discovery = response.json()
    assert discovery["jwks_uri"] == config.resolved_jwks_uri()
    assert discovery["token_endpoint"] == config.resolved_token_endpoint()


def test_mapping_uses_the_configured_issuer() -> None:
    assert ISSUER is not None
    config = ZitadelConfig(issuer=ISSUER, audience="jdlib-api", leeway=timedelta(seconds=5))
    mapping = JwtClaimMapping(issuer=config.issuer, audience=config.audience)
    validator = JwtTokenValidator(
        mapping=mapping,
        keys=JwksCache(
            url=config.resolved_jwks_uri(),
            ttl=config.jwks_ttl,
            fetcher=HttpJwksFetcher(url=config.resolved_jwks_uri()),
        ),
        leeway=config.leeway,
    )
    assert validator.keys.url == f"{ISSUER}/oauth/v2/keys"
    assert validator.mapping.issuer == ISSUER
