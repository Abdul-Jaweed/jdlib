"""Phase 4: gateway adapters (directive §18, §19; spec #12).

The security property under test: an identity is trusted **only** when the
channel it arrived on is authenticated. Concretely:

* with no gateway configured, identity headers are ignored entirely — a direct
  caller cannot impersonate anyone by adding headers,
* a shared-secret assertion is trusted only when the secret matches, the
  assertion is complete, and its validity window is sane,
* a signed (HMAC) assertion is trusted only when the signature verifies over the
  exact identity fields, so tampering with the subject, tenant, scopes or
  timestamps invalidates it,
* a signature configuration cannot be downgraded to a shared secret, and a
  shared-secret configuration cannot be satisfied by a signature header,
* no configuration may claim a gateway it does not verify: NONE with a secret,
  or a secret-bearing mode without a strong secret, is rejected at construction.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import time
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr, ValidationError

from jdlib.security.errors import SecurityConfigurationError
from jdlib.security.gateway.adapters import (
    KongGatewayAdapter,
    NoGatewayAdapter,
    TykGatewayAdapter,
)
from jdlib.security.gateway.config import GatewayConfig, GatewayMode
from jdlib.security.interfaces import GatewayAdapter, GatewayIdentity
from jdlib.tenancy.resolution import RequestInfo

SECRET = "gateway-shared-secret-with-at-least-32-bytes"
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return NOW


def _request(**headers: str) -> RequestInfo:
    return RequestInfo(
        headers={key.lower().replace("_", "-"): value for key, value in headers.items()},
        query={},
        path="/documents/doc-42",
        host="api.example.com",
    )


def _identity_headers(
    *,
    subject: str = "service-1",
    tenant: str | None = "acme",
    scopes: str = "documents:read documents:write",
    issued_at: int | None = None,
    expires_at: int | None = None,
) -> dict[str, str]:
    issued = int((NOW - timedelta(seconds=5)).timestamp()) if issued_at is None else issued_at
    expires = int((NOW + timedelta(seconds=55)).timestamp()) if expires_at is None else expires_at
    headers = {
        "x-jdlib-subject": subject,
        "x-jdlib-scopes": scopes,
        "x-jdlib-issued-at": str(issued),
        "x-jdlib-expires-at": str(expires),
    }
    if tenant is not None:
        headers["x-jdlib-tenant"] = tenant
    return headers


def _signature(headers: dict[str, str], *, secret: str = SECRET) -> str:
    subject = headers["x-jdlib-subject"]
    tenant = headers.get("x-jdlib-tenant", "")
    scopes = ",".join(sorted(headers["x-jdlib-scopes"].replace(",", " ").split()))
    canonical = "\n".join(
        [subject, tenant, scopes, headers["x-jdlib-issued-at"], headers["x-jdlib-expires-at"]]
    )
    return hmac_module.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def _config(mode: GatewayMode, **overrides: object) -> GatewayConfig:
    values: dict[str, object] = {"mode": mode}
    if mode is not GatewayMode.NONE:
        values["secret"] = SecretStr(SECRET)
    values.update(overrides)
    return GatewayConfig(**values)  # type: ignore[arg-type]


def _adapter(cls: type, mode: GatewayMode = GatewayMode.SHARED_SECRET, **overrides: object):
    return cls(config=_config(mode, **overrides), clock=FixedClock())


# --- configuration -----------------------------------------------------------


def test_none_mode_must_not_carry_a_secret() -> None:
    with pytest.raises(SecurityConfigurationError):
        _config(GatewayMode.NONE, secret=SecretStr(SECRET))


@pytest.mark.parametrize("mode", [GatewayMode.SHARED_SECRET, GatewayMode.HMAC])
def test_secret_modes_require_a_secret(mode: GatewayMode) -> None:
    with pytest.raises(SecurityConfigurationError):
        GatewayConfig(mode=mode)


@pytest.mark.parametrize("mode", [GatewayMode.SHARED_SECRET, GatewayMode.HMAC])
def test_short_secrets_are_rejected(mode: GatewayMode) -> None:
    with pytest.raises(SecurityConfigurationError):
        GatewayConfig(mode=mode, secret=SecretStr("too-short"))


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _config(GatewayMode.SHARED_SECRET, trust_headers=True)


def test_max_skew_must_be_positive() -> None:
    with pytest.raises(SecurityConfigurationError):
        _config(GatewayMode.SHARED_SECRET, max_skew=timedelta(0))


def test_header_names_are_lowercase() -> None:
    config = _config(GatewayMode.SHARED_SECRET, subject_header="X-JDLIB-Subject")
    assert config.subject_header == "x-jdlib-subject"


def test_config_repr_never_contains_the_secret() -> None:
    config = _config(GatewayMode.SHARED_SECRET)
    text = f"{config!r} {config.model_dump()} {config.model_dump_json()}"
    assert SECRET not in text


# --- no gateway --------------------------------------------------------------


async def test_no_gateway_ignores_identity_headers() -> None:
    adapter = NoGatewayAdapter()
    request = _request(**_identity_headers(), x_jdlib_gateway_secret=SECRET)
    assert await adapter.verify_identity(request) is None


def test_no_gateway_satisfies_the_port() -> None:
    assert isinstance(NoGatewayAdapter(), GatewayAdapter)
    assert NoGatewayAdapter().name == "none"


# --- shared secret -----------------------------------------------------------


async def test_shared_secret_assertion_is_accepted() -> None:
    adapter = _adapter(KongGatewayAdapter)
    request = _request(**_identity_headers(), x_jdlib_gateway_secret=SECRET)
    identity = await adapter.verify_identity(request)
    assert isinstance(identity, GatewayIdentity)
    assert identity.subject == "service-1"
    assert identity.tenant_slug == "acme"
    assert identity.scopes == frozenset({"documents:read", "documents:write"})
    assert identity.is_valid_at(NOW) is True


async def test_wrong_or_missing_secret_is_refused() -> None:
    adapter = _adapter(KongGatewayAdapter)
    wrong = _request(**_identity_headers(), x_jdlib_gateway_secret=SECRET + "-wrong")
    absent = _request(**_identity_headers())
    forged = _request(**_identity_headers(), x_jdlib_gateway_secret="")
    assert await adapter.verify_identity(wrong) is None
    assert await adapter.verify_identity(absent) is None
    assert await adapter.verify_identity(forged) is None


async def test_incomplete_assertions_are_refused() -> None:
    adapter = _adapter(KongGatewayAdapter)
    missing_subject = _identity_headers()
    del missing_subject["x-jdlib-subject"]
    for headers in (
        missing_subject,
        {**_identity_headers(), "x-jdlib-issued-at": "not-a-timestamp"},
        {**_identity_headers(), "x-jdlib-expires-at": ""},
    ):
        request = _request(**headers, x_jdlib_gateway_secret=SECRET)
        assert await adapter.verify_identity(request) is None


async def test_expired_and_not_yet_valid_assertions_are_refused() -> None:
    adapter = _adapter(KongGatewayAdapter)
    expired = _identity_headers(
        issued_at=int((NOW - timedelta(minutes=10)).timestamp()),
        expires_at=int((NOW - timedelta(minutes=5)).timestamp()),
    )
    future = _identity_headers(
        issued_at=int((NOW + timedelta(minutes=5)).timestamp()),
        expires_at=int((NOW + timedelta(minutes=10)).timestamp()),
    )
    for headers in (expired, future):
        request = _request(**headers, x_jdlib_gateway_secret=SECRET)
        assert await adapter.verify_identity(request) is None


async def test_an_over_long_validity_window_is_refused() -> None:
    # a valid-but-ancient window is a replay: bound it by max_skew
    adapter = _adapter(KongGatewayAdapter, max_skew=timedelta(seconds=60))
    headers = _identity_headers(
        issued_at=int((NOW - timedelta(hours=5)).timestamp()),
        expires_at=int((NOW + timedelta(hours=5)).timestamp()),
    )
    request = _request(**headers, x_jdlib_gateway_secret=SECRET)
    assert await adapter.verify_identity(request) is None


async def test_tenant_is_optional_and_scopes_parse_in_both_separators() -> None:
    adapter = _adapter(KongGatewayAdapter)
    no_tenant = _request(
        **_identity_headers(tenant=None, scopes="documents:read,documents:write"),
        x_jdlib_gateway_secret=SECRET,
    )
    identity = await adapter.verify_identity(no_tenant)
    assert identity is not None
    assert identity.tenant_slug is None
    assert identity.scopes == frozenset({"documents:read", "documents:write"})
    empty = _request(**_identity_headers(scopes=""), x_jdlib_gateway_secret=SECRET)
    empty_identity = await adapter.verify_identity(empty)
    assert empty_identity is not None
    assert empty_identity.scopes == frozenset()


# --- signed identity ---------------------------------------------------------


async def test_signed_identity_is_accepted() -> None:
    adapter = _adapter(KongGatewayAdapter, mode=GatewayMode.HMAC)
    headers = _identity_headers()
    request = _request(**headers, x_jdlib_signature=_signature(headers))
    identity = await adapter.verify_identity(request)
    assert identity is not None
    assert identity.subject == "service-1"


async def test_a_tampered_signed_assertion_is_refused() -> None:
    adapter = _adapter(KongGatewayAdapter, mode=GatewayMode.HMAC)
    headers = _identity_headers()
    signature = _signature(headers)
    for field, value in (
        ("x-jdlib-subject", "admin-service"),
        ("x-jdlib-tenant", "other-tenant"),
        ("x-jdlib-scopes", "documents:read documents:write tenants:admin"),
        ("x-jdlib-expires-at", str(int((NOW + timedelta(hours=2)).timestamp()))),
    ):
        request = _request(**{**headers, field: value}, x_jdlib_signature=signature)
        assert await adapter.verify_identity(request) is None


async def test_a_signature_from_another_secret_is_refused() -> None:
    adapter = _adapter(KongGatewayAdapter, mode=GatewayMode.HMAC)
    headers = _identity_headers()
    other_secret = "another-32-byte-secret-value-x"
    request = _request(**headers, x_jdlib_signature=_signature(headers, secret=other_secret))
    assert await adapter.verify_identity(request) is None


async def test_signature_mode_cannot_be_downgraded_to_a_shared_secret() -> None:
    adapter = _adapter(KongGatewayAdapter, mode=GatewayMode.HMAC)
    request = _request(**_identity_headers(), x_jdlib_gateway_secret=SECRET)
    assert await adapter.verify_identity(request) is None


async def test_shared_secret_mode_is_not_satisfied_by_a_signature() -> None:
    adapter = _adapter(KongGatewayAdapter, mode=GatewayMode.SHARED_SECRET)
    headers = _identity_headers()
    request = _request(**headers, x_jdlib_signature=_signature(headers))
    assert await adapter.verify_identity(request) is None


async def test_a_missing_signature_is_refused() -> None:
    adapter = _adapter(KongGatewayAdapter, mode=GatewayMode.HMAC)
    assert await adapter.verify_identity(_request(**_identity_headers())) is None


# --- product adapters --------------------------------------------------------


def test_product_adapters_use_their_own_header_conventions() -> None:
    kong = _adapter(KongGatewayAdapter)
    tyk = _adapter(TykGatewayAdapter)
    assert kong.name == "kong"
    assert tyk.name == "tyk"
    assert kong.subject_header == "x-jdlib-subject"
    assert tyk.subject_header == "x-tyk-jdlib-subject"
    assert isinstance(kong, GatewayAdapter)
    assert isinstance(tyk, GatewayAdapter)


async def test_product_header_overrides_are_honoured() -> None:
    adapter = _adapter(KongGatewayAdapter, subject_header="x-consumer-username")
    headers = _identity_headers()
    del headers["x-jdlib-subject"]
    request = _request(
        **headers, x_consumer_username="service-1", x_jdlib_gateway_secret=SECRET
    )
    identity = await adapter.verify_identity(request)
    assert identity is not None
    assert identity.subject == "service-1"


def test_adapter_repr_hides_the_secret() -> None:
    assert SECRET not in repr(_adapter(KongGatewayAdapter))
    assert SECRET not in repr(_adapter(TykGatewayAdapter))
    assert SECRET not in repr(NoGatewayAdapter())


async def test_clock_defaults_to_system_time() -> None:
    from jdlib.security.gateway.adapters import KongGatewayAdapter as Adapter

    adapter = Adapter(config=_config(GatewayMode.SHARED_SECRET))
    headers = _identity_headers(
        issued_at=int(time.time()) - 5, expires_at=int(time.time()) + 55
    )
    identity = await adapter.verify_identity(
        _request(**headers, x_jdlib_gateway_secret=SECRET)
    )
    assert identity is not None
