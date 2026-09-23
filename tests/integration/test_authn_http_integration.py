"""Layer 2 integration: authentication adapters over real HTTP.

This suite runs a real HTTP server on a real socket (stdlib
``http.server`` in a background thread) and drives the real transports
(:class:`~jdlib.security.authn.transports.HttpJwksFetcher`,
:class:`~jdlib.security.authn.transports.HttpTokenFetcher`) with the real
validator, JWKS cache and token provider. No mock replaces the network path:
requests travel over TCP, are parsed as HTTP, and the JWT signatures are real
RSA signatures verified against the JWKS document the server published.

Covered here (spec #9, #56, #59, #76, #78; directive §8, §34, §35):

* JWKS retrieval and JWT validation over the wire,
* JWKS key rotation (refresh on unknown kid),
* token acquisition, caching (one request for many calls) and invalidation,
* ``private_key_jwt`` with the server verifying the assertion signature,
* invalid credentials failing permanently without retries,
* endpoint outage failing closed, and recovery once it returns.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import to_base64url_uint
from pydantic import SecretStr

from jdlib.authn.oidc import JwksCache
from jdlib.errors import ExpiredToken, InvalidToken
from jdlib.security.authn.jwt import JwtClaimMapping, JwtTokenValidator
from jdlib.security.authn.provider import (
    ClientAuthMethod,
    ClientCredentialsConfig,
    ClientCredentialsTokenProvider,
    TokenAcquisitionError,
    TokenEndpointUnavailable,
)
from jdlib.security.authn.transports import HttpJwksFetcher, HttpTokenFetcher

pytestmark = pytest.mark.integration

CLIENT_ID = "service-account-integration"
CLIENT_SECRET = "integration-client-secret-never-logged"
ACCESS_TOKEN = "integration-access-token-never-logged"
AUDIENCE = "jdlib-api"
TS = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


class _QuietServer(ThreadingHTTPServer):
    """Threading server that does not print handler tracebacks."""

    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        return  # client disconnects are expected in failure-path tests


class IdentityProvider:
    """A real HTTP identity provider: JWKS + token endpoint, with knobs."""

    def __init__(self) -> None:
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._kid = "kid-1"
        self.jwks_requests = 0
        self.token_requests = 0
        self.token_forms: list[dict[str, str]] = []
        self.token_headers: list[dict[str, str]] = []
        self.reject_credentials = False
        self.broken = False
        self.assertion_verified: bool | None = None
        self._server = _QuietServer(("127.0.0.1", 0), self._handler())
        self._server.daemon_threads = True
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._running = False

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if not self._running:
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            self._running = True

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self._server.shutdown()
        self._thread.join(timeout=5)
        self._server.server_close()  # release the listening socket

    def restart(self, port: int | None = None) -> None:
        """Stop (if running) and listen again, optionally on a fixed port."""
        self.stop()
        self._server = _QuietServer(("127.0.0.1", port or 0), self._handler())
        self.port = int(self._server.server_address[1])
        self.start()

    # -- endpoints ---------------------------------------------------------

    @property
    def issuer(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def public_jwk(self) -> dict[str, object]:
        public = self._key.public_key().public_numbers()
        return {
            "kid": self._kid,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": to_base64url_uint(public.n).decode(),
            "e": to_base64url_uint(public.e).decode(),
        }

    def rotate_key(self) -> None:
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._kid = f"kid-{uuid.uuid4().hex[:8]}"

    def issue_token(self, *, expires_in: int = 300, audience: str = AUDIENCE) -> str:
        now = datetime.now(UTC)
        return pyjwt.encode(
            {
                "iss": self.issuer,
                "aud": audience,
                "sub": "user-integration",
                "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
                "iat": int(now.timestamp()),
                "nbf": int(now.timestamp()),
                "scope": "documents:read documents:write",
            },
            self._key,
            algorithm="RS256",
            headers={"kid": self._kid},
        )

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        provider = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"  # no keep-alive: no lingering connections

            def log_message(self, *args: Any) -> None:  # keep test output pristine
                return

            def _send(self, status: int, payload: dict[str, object]) -> None:
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                if self.path == "/oauth/v2/keys":
                    provider.jwks_requests += 1
                    self._send(200, {"keys": [provider.public_jwk()]})
                    return
                self._send(404, {"error": "not_found"})

            def do_POST(self) -> None:  # noqa: N802 - http.server API
                length = int(self.headers.get("content-length", "0"))
                raw = self.rfile.read(length).decode()
                if self.path != "/oauth/v2/token":
                    self._send(404, {"error": "not_found"})
                    return
                provider.token_requests += 1
                provider.token_forms.append(dict(parse_qs(raw)))
                provider.token_headers.append(
                    {key.lower(): value for key, value in self.headers.items()}
                )
                if provider.broken:
                    self._send(503, {"error": "temporarily_unavailable"})
                    return
                form = parse_qs(raw)
                if not provider._client_authenticated(form, self.headers):
                    self._send(401, {"error": "invalid_client"})
                    return
                self._send(
                    200,
                    {
                        "access_token": ACCESS_TOKEN,
                        "token_type": "Bearer",
                        "expires_in": 300,
                    },
                )

        return Handler

    def _client_authenticated(self, form: dict[str, list[str]], headers: Any) -> bool:
        if self.reject_credentials:
            return False
        if "client_assertion" in form:
            assertion = form["client_assertion"][0]
            try:
                pyjwt.decode(
                    assertion,
                    self._key.public_key(),
                    algorithms=["RS256"],
                    audience=f"{self.issuer}/oauth/v2/token",
                    issuer=CLIENT_ID,
                    options={"verify_exp": False},
                )
            except pyjwt.PyJWTError:
                self.assertion_verified = False
                return False
            self.assertion_verified = True
            return True
        return (
            form.get("client_secret", [""])[0] == CLIENT_SECRET
            and form.get("client_id", [""])[0] == CLIENT_ID
        )


@pytest.fixture
def idp() -> Iterator[IdentityProvider]:
    provider = IdentityProvider()
    provider.start()
    try:
        yield provider
    finally:
        provider.stop()


def _validator(idp: IdentityProvider, **overrides: object) -> JwtTokenValidator:
    values: dict[str, object] = {
        "url": f"{idp.issuer}/oauth/v2/keys",
        "ttl": timedelta(hours=1),
        "fetcher": HttpJwksFetcher(url=f"{idp.issuer}/oauth/v2/keys"),
        # rotation responsiveness is the behaviour under test; the refresh
        # rate limit is covered by unit tests
        "min_refresh_interval": timedelta(0),
    }
    values.update(overrides)
    return JwtTokenValidator(
        mapping=JwtClaimMapping(issuer=idp.issuer, audience=AUDIENCE),
        keys=JwksCache(**values),  # type: ignore[arg-type]
        leeway=timedelta(seconds=30),
    )


def _provider(idp: IdentityProvider, **overrides: object) -> ClientCredentialsTokenProvider:
    values: dict[str, object] = {
        "token_endpoint": f"{idp.issuer}/oauth/v2/token",
        "client_id": CLIENT_ID,
        "client_secret": SecretStr(CLIENT_SECRET),
        "audience": AUDIENCE,
        "scopes": ("documents:read",),
    }
    values.update(overrides)
    config = ClientCredentialsConfig(**values)  # type: ignore[arg-type]
    return ClientCredentialsTokenProvider(
        config=config,
        fetch=HttpTokenFetcher(endpoint=config.token_endpoint),
    )


# --- JWKS and validation over the wire --------------------------------------


async def test_token_validation_over_real_http(idp: IdentityProvider) -> None:
    token = idp.issue_token()
    result = await _validator(idp).validate(token)
    assert result.subject == "user-integration"
    assert result.metadata.issuer == idp.issuer
    assert result.scopes == frozenset({"documents:read", "documents:write"})
    assert idp.jwks_requests == 1


async def test_jwks_is_cached_across_validations(idp: IdentityProvider) -> None:
    validator = _validator(idp)
    for _ in range(5):
        assert (await validator.validate(idp.issue_token())).subject == "user-integration"
    assert idp.jwks_requests == 1


async def test_jwks_rotation_is_picked_up_over_real_http(idp: IdentityProvider) -> None:
    validator = _validator(idp)
    await validator.validate(idp.issue_token())
    idp.rotate_key()
    result = await validator.validate(idp.issue_token())
    assert result.subject == "user-integration"
    assert idp.jwks_requests == 2


async def test_forged_signature_is_rejected_over_real_http(idp: IdentityProvider) -> None:
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = {
        "iss": idp.issuer,
        "aud": AUDIENCE,
        "sub": "attacker",
        "exp": int((TS + timedelta(hours=1)).timestamp()),
    }
    forged = pyjwt.encode(
        claims,
        attacker,
        algorithm="RS256",
        headers={"kid": idp.public_jwk()["kid"]},
    )
    with pytest.raises(InvalidToken):
        await _validator(idp).validate(forged)


async def test_expired_token_is_rejected_over_real_http(idp: IdentityProvider) -> None:
    with pytest.raises(ExpiredToken):
        await _validator(idp).validate(idp.issue_token(expires_in=-60))


async def test_wrong_audience_is_rejected_over_real_http(idp: IdentityProvider) -> None:
    with pytest.raises(InvalidToken):
        await _validator(idp).validate(idp.issue_token(audience="other-api"))


# --- Token acquisition over the wire ----------------------------------------


async def test_token_acquisition_caching_and_invalidation(idp: IdentityProvider) -> None:
    provider = _provider(idp)
    first = await provider.token(audience=AUDIENCE)
    second = await provider.token(audience=AUDIENCE)
    assert first.value.get_secret_value() == ACCESS_TOKEN == second.value.get_secret_value()
    assert idp.token_requests == 1
    assert idp.token_forms[0]["grant_type"] == ["client_credentials"]
    assert idp.token_forms[0]["scope"] == ["documents:read"]
    await provider.invalidate()
    await provider.token(audience=AUDIENCE)
    assert idp.token_requests == 2


async def test_private_key_jwt_is_verified_by_the_server(idp: IdentityProvider) -> None:
    from cryptography.hazmat.primitives import serialization

    pem = idp._key.private_bytes(  # noqa: SLF001 - the server's own key pair
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    provider = _provider(
        idp,
        client_secret=None,
        auth_method=ClientAuthMethod.PRIVATE_KEY_JWT,
        private_key=SecretStr(pem),
    )
    token = await provider.token(audience=AUDIENCE)
    assert token.value.get_secret_value() == ACCESS_TOKEN
    assert idp.assertion_verified is True
    assert "client_secret" not in idp.token_forms[0]


async def test_invalid_credentials_fail_permanently_without_retries(
    idp: IdentityProvider,
) -> None:
    idp.reject_credentials = True
    provider = _provider(idp)
    with pytest.raises(TokenAcquisitionError):
        await provider.token(audience=AUDIENCE)
    assert idp.token_requests == 1  # a 401 is never retried
    assert provider.cache_size() == 0


async def test_endpoint_outage_fails_closed_and_recovers(idp: IdentityProvider) -> None:
    port = idp.port
    provider = _provider(idp, max_attempts=2, retry_backoff=timedelta(milliseconds=10))
    idp.stop()
    with pytest.raises(TokenEndpointUnavailable):
        await provider.token(audience=AUDIENCE)
    # no credential may be handed out while the endpoint is unavailable
    assert provider.cache_size() == 0
    idp.restart(port=port)
    token = await provider.token(audience=AUDIENCE)
    assert token.value.get_secret_value() == ACCESS_TOKEN


async def test_transient_5xx_is_retried_over_real_http(idp: IdentityProvider) -> None:
    idp.broken = True
    provider = _provider(idp, max_attempts=3, retry_backoff=timedelta(milliseconds=10))
    with pytest.raises(TokenEndpointUnavailable):
        await provider.token(audience=AUDIENCE)
    assert idp.token_requests == 3  # bounded retries, then fail closed
    idp.broken = False
    assert (await provider.token(audience=AUDIENCE)).value.get_secret_value() == ACCESS_TOKEN
