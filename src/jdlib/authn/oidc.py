from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, cast

import jwt as pyjwt

from jdlib.config import OidcConfig
from jdlib.context import Clock, SystemClock
from jdlib.errors import ExpiredToken, InvalidToken

JwksFetcher = Callable[[str], Awaitable[Mapping[str, object]]]


class JwksCache:
    def __init__(
        self,
        *,
        url: str,
        ttl: timedelta,
        fetcher: JwksFetcher,
        clock: Clock | None = None,
    ) -> None:
        self._url = url
        self._ttl = ttl
        self._fetcher = fetcher
        self._clock = clock or SystemClock()
        self._fetched_at: datetime | None = None
        self._keys: dict[str, object] = {}

    async def _refresh(self) -> None:
        document = await self._fetcher(self._url)
        raw_keys = document.get("keys")
        keys: dict[str, object] = {}
        if isinstance(raw_keys, list):
            for jwk in raw_keys:
                if not isinstance(jwk, Mapping):
                    continue
                kid = jwk.get("kid")
                if kid:
                    keys[str(kid)] = jwk
        self._keys = keys
        self._fetched_at = self._clock.now()

    def _stale(self) -> bool:
        if self._fetched_at is None:
            return True
        return self._clock.now() - self._fetched_at > self._ttl

    async def signing_key(self, kid: str) -> object | None:
        if self._stale() or kid not in self._keys:
            await self._refresh()
        jwk = self._keys.get(kid)
        if not isinstance(jwk, Mapping):
            return None
        try:
            return cast(object, pyjwt.PyJWK.from_dict(dict(jwk)).key)
        except (pyjwt.PyJWKError, ValueError, KeyError):
            return None


class TokenVerifier:
    def __init__(self, config: OidcConfig, clock: Clock | None = None) -> None:
        self._config = config
        self._clock = clock or SystemClock()

    def verify(self, token: str, key: object) -> Mapping[str, object]:
        try:
            claims = pyjwt.decode(
                token,
                cast(Any, key),
                algorithms=self._config.algorithms,
                audience=self._config.audience,
                issuer=self._config.issuer,
                leeway=self._config.leeway.total_seconds(),
                options={"verify_exp": False, "verify_nbf": False, "verify_iat": False},
            )
        except pyjwt.PyJWTError as exc:
            raise InvalidToken(f"token verification failed: {type(exc).__name__}") from exc
        self._validate_times(claims)
        return claims

    def _validate_times(self, claims: Mapping[str, Any]) -> None:
        now = self._clock.now().timestamp()
        leeway = self._config.leeway.total_seconds()
        exp = self._timestamp(claims, "exp")
        if exp is not None and exp <= now - leeway:
            raise ExpiredToken("token expired")
        nbf = self._timestamp(claims, "nbf")
        if nbf is not None and nbf > now + leeway:
            raise InvalidToken("token not yet valid")
        iat = self._timestamp(claims, "iat")
        if iat is not None and iat > now + leeway:
            raise InvalidToken("token issued in the future")

    @staticmethod
    def _timestamp(claims: Mapping[str, Any], name: str) -> int | None:
        value = claims.get(name)
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            raise InvalidToken(f"invalid {name} claim") from None


@dataclass(frozen=True, slots=True)
class IdentityClaims:
    issuer: str
    subject: str
    email: str | None
    email_verified: bool


class ClaimMapper:
    def __init__(self, config: OidcConfig) -> None:
        self._config = config

    def map(self, claims: Mapping[str, object]) -> IdentityClaims:
        email = claims.get("email")
        verified = claims.get("email_verified")
        return IdentityClaims(
            issuer=str(claims.get("iss", self._config.issuer)),
            subject=str(claims["sub"]),
            email=str(email) if isinstance(email, str) else None,
            email_verified=bool(verified) if isinstance(verified, bool) else False,
        )
