from jdlib.authn.apikey import ApiKeyAuthenticator
from jdlib.authn.composite import CompositeAuthenticator
from jdlib.authn.oidc import OidcAuthenticator
from jdlib.authn.wiring import build_authenticator
from jdlib.config import TenancyConfig
from jdlib.control.audit import RecordingPlatformAudit


def _session_factory():
    raise AssertionError("session factory must not be used during assembly")


def _authenticator_types(composite: CompositeAuthenticator) -> list[type]:
    return [type(part) for part in composite._authenticators]


def test_build_authenticator_includes_oidc_then_api_keys():
    config = TenancyConfig(
        context={"signing_key": "k"},
        oidc={"issuer": "https://idp.example.com", "audience": "jdlib"},
    )
    authenticator = build_authenticator(config, _session_factory, RecordingPlatformAudit())
    assert isinstance(authenticator, CompositeAuthenticator)
    assert _authenticator_types(authenticator) == [OidcAuthenticator, ApiKeyAuthenticator]


def test_build_authenticator_skips_oidc_when_absent():
    config = TenancyConfig(context={"signing_key": "k"})
    authenticator = build_authenticator(config, _session_factory, RecordingPlatformAudit())
    assert isinstance(authenticator, CompositeAuthenticator)
    assert _authenticator_types(authenticator) == [ApiKeyAuthenticator]
