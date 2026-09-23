"""Phase 2: JWKS cache hardening.

Spec refs: #9 (JWKS security: cache TTL, refresh-on-unknown-kid,
stale-if-available, concurrency control, thundering-herd protection, timeout,
failure handling, algorithm allowlist), #59 (bounded caches with failure
behaviour), #60 (concurrency), #78 (explicit timeouts).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import to_base64url_uint

from jdlib.authn.oidc import JwksCache
from jdlib.security.authn.algorithms import assert_safe_algorithms
from jdlib.security.errors import SecurityConfigurationError


def _rsa_jwk(kid: str = "k1") -> dict[str, object]:
    """A real RSA public JWK, so key conversion exercises the real code path."""
    numbers = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    public = numbers.public_numbers()
    return {
        "kid": kid,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": to_base64url_uint(public.n).decode(),
        "e": to_base64url_uint(public.e).decode(),
    }


JWK = _rsa_jwk()
PUBLIC_MODULUS = str(JWK["n"])


class Clock:
    def __init__(self) -> None:
        self._now = datetime(2026, 1, 1, tzinfo=UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta


class Fetcher:
    """Records fetch attempts; can succeed, fail, or hang."""

    def __init__(self, document: Mapping[str, object] | None = None) -> None:
        self.calls = 0
        self.document: Mapping[str, object] = document or {"keys": [JWK]}
        self.error: Exception | None = None
        self.hang = False

    async def __call__(self, url: str) -> Mapping[str, object]:
        self.calls += 1
        await asyncio.sleep(0)
        if self.hang:
            await asyncio.Event().wait()
        if self.error is not None:
            raise self.error
        return self.document


FetcherFactory = Callable[[], Awaitable[Mapping[str, object]]]


def _cache(fetcher: FetcherFactory, clock: Clock, **kwargs: object) -> JwksCache:
    return JwksCache(
        url="https://idp.example.com/.well-known/jwks.json",
        ttl=timedelta(hours=1),
        fetcher=fetcher,
        clock=clock,
        **kwargs,  # type: ignore[arg-type]
    )


# --- Thundering-herd protection --------------------------------------------


def test_concurrent_unknown_kid_lookups_trigger_a_single_fetch() -> None:
    async def scenario() -> int:
        clock = Clock()
        fetcher = Fetcher()
        cache = _cache(fetcher, clock)
        await asyncio.gather(*[cache.signing_key("k1") for _ in range(25)])
        return fetcher.calls

    assert asyncio.run(scenario()) == 1


def test_concurrent_stale_lookups_trigger_a_single_fetch() -> None:
    async def scenario() -> int:
        clock = Clock()
        fetcher = Fetcher()
        cache = _cache(fetcher, clock, min_refresh_interval=timedelta(0))
        assert await cache.signing_key("k1") is not None
        clock.advance(timedelta(hours=2))
        await asyncio.gather(*[cache.signing_key("k1") for _ in range(25)])
        return fetcher.calls

    assert asyncio.run(scenario()) == 2


# --- Stale-if-available and failure handling --------------------------------


def test_failed_refresh_keeps_serving_cached_keys() -> None:
    async def scenario() -> object:
        clock = Clock()
        fetcher = Fetcher()
        cache = _cache(fetcher, clock, min_refresh_interval=timedelta(0))
        assert await cache.signing_key("k1") is not None
        fetcher.error = RuntimeError("idp outage")
        clock.advance(timedelta(hours=2))
        return await cache.signing_key("k1")

    assert asyncio.run(scenario()) is not None


def test_failed_refresh_surfaces_the_cause_for_unknown_kids() -> None:
    async def scenario() -> BaseException | None:
        clock = Clock()
        fetcher = Fetcher()
        fetcher.error = RuntimeError("idp outage")
        cache = _cache(fetcher, clock)
        try:
            await cache.signing_key("never-seen")
        except BaseException as exc:  # noqa: BLE001 - asserting the cause
            return exc
        return None

    cause = asyncio.run(scenario())
    assert isinstance(cause, RuntimeError)
    assert str(cause) == "idp outage"


def test_failed_refresh_is_not_retried_before_min_refresh_interval() -> None:
    async def scenario() -> int:
        clock = Clock()
        fetcher = Fetcher()
        fetcher.error = RuntimeError("idp outage")
        cache = _cache(fetcher, clock, min_refresh_interval=timedelta(seconds=5))
        for _ in range(3):
            with pytest.raises(RuntimeError):
                await cache.signing_key("never-seen")
        return fetcher.calls

    assert asyncio.run(scenario()) == 1


def test_refresh_timeout_does_not_hang_the_request() -> None:
    async def scenario() -> BaseException | None:
        clock = Clock()
        fetcher = Fetcher()
        fetcher.hang = True
        cache = _cache(fetcher, clock, timeout=timedelta(milliseconds=50))
        try:
            await asyncio.wait_for(cache.signing_key("k1"), timeout=1.0)
        except BaseException as exc:  # noqa: BLE001 - asserting the cause
            return exc
        return None

    cause = asyncio.run(scenario())
    assert isinstance(cause, TimeoutError)


def test_timeout_after_success_still_serves_cached_keys() -> None:
    async def scenario() -> object:
        clock = Clock()
        fetcher = Fetcher()
        cache = _cache(
            fetcher, clock, timeout=timedelta(milliseconds=50), min_refresh_interval=timedelta(0)
        )
        assert await cache.signing_key("k1") is not None
        fetcher.hang = True
        clock.advance(timedelta(hours=2))
        return await asyncio.wait_for(cache.signing_key("k1"), timeout=1.0)

    assert asyncio.run(scenario()) is not None


# --- Readiness and safe introspection ---------------------------------------


def test_ready_reports_key_material_availability() -> None:
    async def scenario() -> tuple[bool, bool]:
        clock = Clock()
        fetcher = Fetcher()
        cache = _cache(fetcher, clock)
        before = await cache.ready()
        await cache.signing_key("k1")
        return before, await cache.ready()

    assert asyncio.run(scenario()) == (False, True)


def test_repr_exposes_cache_state_but_never_key_material() -> None:
    async def scenario() -> str:
        clock = Clock()
        fetcher = Fetcher({"keys": [JWK]})
        cache = _cache(fetcher, clock)
        assert await cache.signing_key("k1") is not None
        return repr(cache)

    rendered = asyncio.run(scenario())
    assert PUBLIC_MODULUS not in rendered
    assert "JwksCache" in rendered
    assert "keys=1" in rendered


# --- Algorithm allowlist ----------------------------------------------------


@pytest.mark.parametrize("algorithm", ["none", "NONE", "None"])
def test_alg_none_is_never_acceptable(algorithm: str) -> None:
    with pytest.raises(SecurityConfigurationError):
        assert_safe_algorithms([algorithm])


@pytest.mark.parametrize("algorithm", ["HS256", "HS384", "HS512"])
def test_symmetric_algorithms_are_rejected_for_jwks_validation(algorithm: str) -> None:
    with pytest.raises(SecurityConfigurationError):
        assert_safe_algorithms([algorithm])


def test_empty_algorithm_list_is_rejected() -> None:
    with pytest.raises(SecurityConfigurationError):
        assert_safe_algorithms([])


@pytest.mark.parametrize(
    "algorithms",
    [["RS256"], ["RS256", "ES256"], ["PS512"], ["EdDSA"], ["RS256", "ES256", "EdDSA"]],
)
def test_asymmetric_algorithms_are_accepted(algorithms: list[str]) -> None:
    assert_safe_algorithms(algorithms)
