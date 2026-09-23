import uuid

import pytest
from pydantic import ValidationError

from jdlib.authn.base import Authenticator, bearer_token
from jdlib.authn.composite import CompositeAuthenticator
from jdlib.config import ApiKeyConfig, OidcConfig, TenancyConfig
from jdlib.context import Principal, PrincipalKind
from jdlib.tenancy.resolution import RequestInfo


def _request(headers: dict[str, str] | None = None) -> RequestInfo:
    return RequestInfo(headers=headers or {}, query={}, path="/", host="app.example.com")


def test_oidc_config_defaults():
    config = OidcConfig(issuer="https://idp.example.com", audience="jdlib")
    assert config.algorithms == ["RS256"]
    assert config.jwks_ttl.total_seconds() == 3600
    assert config.leeway.total_seconds() == 60
    assert config.email_trusted is False
    assert config.jwks_url is None
    assert config.resolved_jwks_url() == "https://idp.example.com/.well-known/jwks.json"


def test_oidc_config_requires_issuer_and_audience():
    with pytest.raises(ValidationError):
        OidcConfig()


def test_tenancy_config_includes_auth_blocks():
    config = TenancyConfig(
        context={"signing_key": "k"},
        oidc={"issuer": "https://idp", "audience": "a"},
    )
    assert config.oidc is not None
    assert config.api_keys == ApiKeyConfig()


def test_bearer_token_extraction():
    assert bearer_token(_request({"authorization": "Bearer abc.def"})) == "abc.def"
    assert bearer_token(_request({"authorization": "bearer abc"})) == "abc"
    assert bearer_token(_request({"authorization": "Basic abc"})) is None
    assert bearer_token(_request()) is None


def test_bearer_token_splits_on_any_whitespace_and_rejects_empty_values():
    assert bearer_token(_request({"authorization": "Bearer\tabc.def"})) == "abc.def"
    assert bearer_token(_request({"authorization": "Bearer   abc"})) == "abc"
    assert bearer_token(_request({"authorization": "Bearer \t abc"})) == "abc"
    assert bearer_token(_request({"authorization": "Bearer "})) is None
    assert bearer_token(_request({"authorization": "Bearer\t"})) is None
    assert bearer_token(_request({"authorization": "Bearer"})) is None
    assert bearer_token(_request({"authorization": "   "})) is None


class _Authenticator:
    def __init__(self, principal: Principal | None) -> None:
        self._principal = principal
        self.calls = 0

    async def authenticate(self, request: RequestInfo) -> Principal | None:
        self.calls += 1
        return self._principal


async def test_composite_returns_first_principal():
    principal = Principal(kind=PrincipalKind.USER, id=uuid.uuid4())
    first = _Authenticator(None)
    second = _Authenticator(principal)
    third = _Authenticator(principal)
    composite = CompositeAuthenticator([first, second, third])
    assert await composite.authenticate(_request()) is principal
    assert first.calls == 1 and second.calls == 1 and third.calls == 0


async def test_composite_returns_none_when_all_fail():
    composite = CompositeAuthenticator([_Authenticator(None), _Authenticator(None)])
    assert await composite.authenticate(_request()) is None


def test_authenticator_protocol_shape():
    assert hasattr(Authenticator, "authenticate")
