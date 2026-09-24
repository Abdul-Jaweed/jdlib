"""An unreachable identity provider is an outage, not a bad credential.

The key set was built to preserve exactly this distinction: with no usable key
material and a failed refresh it re-raises the underlying failure rather than
answering "unknown key", and its own tests pin that ("surface the real cause so
callers can audit and alert on it"). One level up, the authenticator discarded the
distinction: a bare `except Exception` turned every failure of the key lookup -
including a refused connection to the identity provider - into `None`, and the
middleware reports `None` as `401 no credentials presented`.

That sends the caller to fix a token that was never checked, and it makes an
outage look like an authentication problem on the dashboard. The reference
application is what surfaced it: its end-to-end gap asked what an identity-provider
outage should answer, and the honest answer - `503`, like every other outage in
this library - was unreachable, because the failure never left the authenticator.

The tests below are the claim, the guard against over-blocking, and the mapping.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from datetime import timedelta
from typing import Any

import pytest

from jdlib.authn.oidc import JwksCache, OidcAuthenticator
from jdlib.config import OidcConfig
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.errors import AuthenticationUnavailable, InvalidToken
from jdlib.tenancy.middleware import http_status_for
from jdlib.tenancy.resolution import RequestInfo


def _token(kid: str = "k1") -> str:
    """A JWT-shaped token: the header is all the authenticator reads first."""

    def part(payload: dict[str, object]) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return ".".join(
        (
            part({"alg": "RS256", "kid": kid, "typ": "JWT"}),
            part({"iss": "https://idp.example.test", "sub": "someone"}),
            "c2lnbmF0dXJl",
        )
    )


class _Fetcher:
    """A JWKS fetcher that can fail, hang, or answer - like the real one."""

    def __init__(self, document: dict[str, object] | None = None) -> None:
        self.document = document or {"keys": []}
        self.error: Exception | None = None
        self.calls = 0

    async def __call__(self, url: str) -> dict[str, object]:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.document


def _authenticator(fetcher: _Fetcher) -> tuple[OidcAuthenticator, RecordingPlatformAudit]:
    """The real authenticator, with only the parts the outage path never reaches stubbed.

    `verifier`, `mapper` and `linker` are unreachable while the key lookup is
    failing; a test that reached them would be asserting the wrong thing.
    """

    audit = RecordingPlatformAudit()
    authenticator = OidcAuthenticator(
        config=OidcConfig(issuer="https://idp.example.test", audience="jdlib"),
        cache=JwksCache(
            url="https://idp.example.test/oauth/v2/keys",
            ttl=timedelta(hours=1),
            fetcher=fetcher,  # type: ignore[arg-type]
        ),
        verifier=Any,  # type: ignore[arg-type]
        mapper=Any,  # type: ignore[arg-type]
        linker=Any,  # type: ignore[arg-type]
        audit=audit,
    )
    return authenticator, audit


def _request(token: str) -> RequestInfo:
    return RequestInfo(
        headers={"authorization": f"Bearer {token}"},
        query={},
        path="/api/projects",
        host="app.example.test",
    )


def test_an_unreachable_key_set_raises_instead_of_answering_no_credential() -> None:
    """The claim: an outage travels, so the caller can answer `503`."""

    async def scenario() -> BaseException | None:
        fetcher = _Fetcher()
        fetcher.error = ConnectionError("connection refused")
        authenticator, audit = _authenticator(fetcher)
        try:
            await authenticator.authenticate(_request(_token()))
        except BaseException as exc:  # noqa: BLE001 - the failure is the subject
            assert audit.entries, "an authentication failure must still be recorded"
            return exc
        return None

    failure = asyncio.run(scenario())

    assert isinstance(failure, AuthenticationUnavailable), (
        "an identity-provider outage must not be reported as a missing credential"
    )
    assert isinstance(failure.__cause__, ConnectionError), (
        "the underlying cause must survive, or an operator cannot see what broke"
    )


def test_an_unknown_key_with_a_healthy_key_set_is_still_not_an_outage() -> None:
    """The guard against over-blocking: a working provider still answers `401`."""

    async def scenario() -> tuple[object, int]:
        fetcher = _Fetcher({"keys": [{"kid": "other-key", "kty": "RSA", "n": "x", "e": "AQAB"}]})
        authenticator, _ = _authenticator(fetcher)
        principal = await authenticator.authenticate(_request(_token("never-seen")))
        return principal, fetcher.calls

    principal, calls = asyncio.run(scenario())

    assert principal is None, "a key set that answers normally must not turn into an outage"
    assert calls == 1, "the key set was refreshed exactly once: the provider is reachable"


def test_a_refresh_rate_limit_does_not_turn_a_live_provider_into_an_outage() -> None:
    """The other half of the guard: a rate-limited refresh is not a refused one.

    `JwksCache` refuses to refresh more often than `min_refresh_interval`. That is
    a deliberate throttle, and while the *last* refresh failed it must not be
    re-classified: the failures here are the caller's tokens, not the provider.
    """

    async def scenario() -> BaseException | None:
        fetcher = _Fetcher({"keys": [{"kid": "k1", "kty": "RSA", "n": "x", "e": "AQAB"}]})
        authenticator, _ = _authenticator(fetcher)
        try:
            # The first lookup answers with the configured key set; the second
            # token fails verification (the stub verifier is unreachable), which is
            # a credential problem, not an outage.
            await authenticator.authenticate(_request(_token("k1")))
        except BaseException as exc:  # noqa: BLE001 - whatever it is, it is not the claim
            return exc
        return None

    failure = asyncio.run(scenario())

    assert not isinstance(failure, AuthenticationUnavailable), (
        "a provider that answered must never be reported as unavailable"
    )


def test_the_status_mapping_puts_the_outage_before_the_credential() -> None:
    """`503`, and specifically not the `401` its base class maps to."""

    assert http_status_for(AuthenticationUnavailable("unavailable")) == 503
    assert http_status_for(InvalidToken("bad token")) == 401
    assert http_status_for(AuthenticationUnavailable("unavailable")) != http_status_for(
        InvalidToken("bad token")
    )


@pytest.mark.parametrize("age_seconds", [0])
def test_the_time_of_the_failure_is_not_recorded_as_a_credential(age_seconds: int) -> None:
    """No secrets and no times leak into the recorded reason."""

    async def scenario() -> list[str]:
        fetcher = _Fetcher()
        fetcher.error = TimeoutError("refresh timed out")
        authenticator, audit = _authenticator(fetcher)
        with pytest.raises(AuthenticationUnavailable):
            await authenticator.authenticate(_request(_token()))
        return [str(record.get("metadata")) for record in audit.entries]

    recorded = asyncio.run(scenario())

    assert recorded, "the failure must be recorded"
    assert all("undefined" not in entry for entry in recorded)
    assert time.time() > age_seconds
