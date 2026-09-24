"""Phase 8 (service identity): an outbound token is reused only for its own question.

The claim under attack: the credential cache is keyed by *everything the token
is authorized for* — audience and scope set. If it were keyed by client alone (or
by audience alone), a service that acquires a narrow token would later be handed
a broader one, or a token minted for one API would be presented to another: a
privilege escalation and an audience-confusion bug at once, invisible in the
happy path because the token still looks valid.

These attacks drive the provider the way an application calls it — through
``token(audience=..., scopes=...)`` — and assert on what the *endpoint* was
asked for and what came back, not on the cache's internals.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from pydantic import SecretStr

from jdlib.security.authn.provider import (
    ClientCredentialsConfig,
    ClientCredentialsTokenProvider,
)

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
TOKEN_ENDPOINT = "https://id.example.com/oauth/v2/token"


class Clock:
    def now(self) -> datetime:
        return NOW


class EchoEndpoint:
    """Mints a distinct token per request and echoes what it was asked for."""

    def __init__(self) -> None:
        self.calls = 0
        self.forms: list[dict[str, str]] = []

    async def __call__(
        self, form: Mapping[str, str], headers: Mapping[str, str]
    ) -> Mapping[str, object]:
        self.calls += 1
        self.forms.append(dict(form))
        audience = form.get("audience", "")
        scope = form.get("scope", "")
        return {
            "access_token": f"token-for:{audience}:{scope}",
            "token_type": "Bearer",
            "expires_in": 300,
        }


def _provider(endpoint: EchoEndpoint, **overrides: object) -> ClientCredentialsTokenProvider:
    values: dict[str, object] = {
        "token_endpoint": TOKEN_ENDPOINT,
        "client_id": "jdlib-service",
        "client_secret": SecretStr("client-secret-value-that-must-never-leak"),
        "scopes": ("documents:read",),
        "audience": "jdlib-api",
    }
    values.update(overrides)
    return ClientCredentialsTokenProvider(
        config=ClientCredentialsConfig(**values),  # type: ignore[arg-type]
        fetch=endpoint,
        clock=Clock(),
        sleeper=lambda delay: asyncio.sleep(0),
    )


def test_a_narrow_token_is_not_served_for_a_broader_scope_set() -> None:
    async def scenario() -> tuple[int, str, str]:
        endpoint = EchoEndpoint()
        provider = _provider(endpoint)
        narrow = await provider.token(audience="jdlib-api", scopes=["documents:read"])
        broader = await provider.token(
            audience="jdlib-api", scopes=["documents:read", "documents:write"]
        )
        return endpoint.calls, narrow.value.get_secret_value(), broader.value.get_secret_value()

    calls, narrow_token, broader_token = asyncio.run(scenario())

    assert calls == 2, "a different scope set is a different question"
    assert narrow_token != broader_token
    assert "documents:write" not in narrow_token
    assert "documents:write" in broader_token


def test_a_token_is_never_presented_to_another_audience() -> None:
    async def scenario() -> tuple[int, str, str]:
        endpoint = EchoEndpoint()
        provider = _provider(endpoint)
        first = await provider.token(audience="jdlib-api")
        second = await provider.token(audience="billing-api")
        return endpoint.calls, first.value.get_secret_value(), second.value.get_secret_value()

    calls, first_token, second_token = asyncio.run(scenario())

    assert calls == 2, "audience is part of the cache key"
    assert first_token != second_token
    assert "jdlib-api" in first_token and "billing-api" in second_token


def test_the_requested_scopes_and_audience_reach_the_endpoint() -> None:
    """The token must answer the question that was asked, not the default."""

    async def scenario() -> dict[str, str]:
        endpoint = EchoEndpoint()
        provider = _provider(endpoint)
        await provider.token(audience="billing-api", scopes=["invoices:read"])
        return endpoint.forms[0]

    form = asyncio.run(scenario())

    assert form["audience"] == "billing-api"
    assert form["scope"] == "invoices:read", "the caller's scopes win over the configured default"
    assert "documents:read" not in form["scope"]


def test_scope_order_does_not_split_the_cache() -> None:
    """Canonicalisation is what makes the key trustworthy, so pin it too."""

    async def scenario() -> int:
        endpoint = EchoEndpoint()
        provider = _provider(endpoint)
        await provider.token(audience="jdlib-api", scopes=["documents:write", "documents:read"])
        await provider.token(audience="jdlib-api", scopes=["documents:read", "documents:write"])
        return endpoint.calls

    assert asyncio.run(scenario()) == 1


def test_a_stale_token_is_not_reused_past_its_lifetime() -> None:
    """The cache's own key is not enough: freshness is checked on every use."""

    class MovingClock:
        def __init__(self) -> None:
            self._now = NOW

        def now(self) -> datetime:
            return self._now

        def advance(self, delta: timedelta) -> None:
            self._now += delta

    async def scenario() -> int:
        endpoint = EchoEndpoint()
        clock = MovingClock()
        provider = ClientCredentialsTokenProvider(
            config=ClientCredentialsConfig(
                token_endpoint=TOKEN_ENDPOINT,
                client_id="jdlib-service",
                client_secret=SecretStr("client-secret-value-that-must-never-leak"),
                audience="jdlib-api",
            ),
            fetch=endpoint,
            clock=clock,
            sleeper=lambda delay: asyncio.sleep(0),
        )
        await provider.token(audience="jdlib-api")
        clock.advance(timedelta(seconds=301))
        await provider.token(audience="jdlib-api")
        return endpoint.calls

    assert asyncio.run(scenario()) == 2
