from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import jwt as pyjwt
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib._uuid import uuid7
from jdlib.authn.base import bearer_token, record_authn_failure
from jdlib.config import OidcConfig
from jdlib.context import Clock, Principal, PrincipalKind, SystemClock
from jdlib.control.audit import PlatformAudit
from jdlib.control.models import IdentityLink, User
from jdlib.control.session import ControlPlaneSession
from jdlib.errors import AuthenticationError, ExpiredToken, InvalidToken
from jdlib.tenancy.resolution import RequestInfo

JwksFetcher = Callable[[str], Awaitable[Mapping[str, object]]]


class JwksCache:
    """Caches JWKS signing keys with hardened refresh behaviour (spec #9).

    * a single in-flight refresh is shared by concurrent lookups
      (thundering-herd protection),
    * refresh failures and refresh timeouts never discard usable key material:
      a known ``kid`` keeps validating from cache (stale-if-available),
    * failed refreshes are rate-limited by ``min_refresh_interval`` so an
      identity-provider outage cannot turn into a request storm,
    * key material never appears in logs or ``repr``,
    * every fetch is bounded by ``timeout`` (spec #78).
    """

    def __init__(
        self,
        *,
        url: str,
        ttl: timedelta,
        fetcher: JwksFetcher,
        clock: Clock | None = None,
        min_refresh_interval: timedelta = timedelta(seconds=1),
        timeout: timedelta = timedelta(seconds=5),
    ) -> None:
        self._url = url
        self._ttl = ttl
        self._fetcher = fetcher
        self._clock = clock or SystemClock()
        self._min_refresh_interval = min_refresh_interval
        self._timeout = timeout
        self._fetched_at: datetime | None = None
        self._last_refresh_attempt: datetime | None = None
        self._keys: dict[str, object] = {}
        self._refresh_lock = asyncio.Lock()
        self._last_failure: str | None = None
        self._last_error: BaseException | None = None

    def __repr__(self) -> str:
        return (
            f"JwksCache(url={self._url!r}, keys={len(self._keys)}, "
            f"stale={self._stale()}, last_failure={self._last_failure!r})"
        )

    async def _fetch(self) -> Mapping[str, object]:
        fetch = self._fetcher(self._url)
        return await asyncio.wait_for(fetch, timeout=self._timeout.total_seconds())

    async def _refresh(self) -> None:
        self._last_refresh_attempt = self._clock.now()
        try:
            document = await self._fetch()
        except Exception as exc:  # noqa: BLE001 - any fetch failure degrades to cache
            self._last_failure = type(exc).__name__
            self._last_error = exc
            return
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
        self._last_failure = None
        self._last_error = None

    def _stale(self) -> bool:
        if self._fetched_at is None:
            return True
        return self._clock.now() - self._fetched_at > self._ttl

    def _can_refresh(self) -> bool:
        if self._last_refresh_attempt is None:
            return True
        return self._clock.now() - self._last_refresh_attempt >= self._min_refresh_interval

    def _needs_refresh(self, kid: str) -> bool:
        return self._stale() or kid not in self._keys

    async def signing_key(self, kid: str) -> object | None:
        if self._needs_refresh(kid) and self._can_refresh():
            async with self._refresh_lock:
                # Re-check under the lock: a concurrent lookup may have refreshed.
                if self._needs_refresh(kid) and self._can_refresh():
                    await self._refresh()
        jwk = self._keys.get(kid)
        key: object | None = None
        if isinstance(jwk, Mapping):
            try:
                key = cast(object, pyjwt.PyJWK.from_dict(dict(jwk)).key)
            except pyjwt.PyJWTError:
                key = None
        if key is not None:
            return key
        if self._last_error is not None:
            # No usable key material and the last refresh failed: surface the
            # real cause (identity-provider outage vs. unknown key) so callers
            # can audit and alert on it. Callers still fail closed.
            raise self._last_error
        return None

    async def ready(self) -> bool:
        """Report whether key material is loaded (spec #51 security readiness)."""
        return bool(self._keys)

    @property
    def url(self) -> str:
        """The JWKS endpoint this cache refreshes from."""
        return self._url

    @property
    def stale(self) -> bool:
        """Operational signal: cached keys are older than the configured TTL."""
        return self._stale()


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
        subject = claims.get("sub")
        if subject is None:
            raise InvalidToken("missing subject")
        return IdentityClaims(
            issuer=str(claims.get("iss", self._config.issuer)),
            subject=str(subject),
            email=str(email) if isinstance(email, str) else None,
            email_verified=bool(verified) if isinstance(verified, bool) else False,
        )


class UserLinker:
    def __init__(
        self, session_factory: Callable[[], AsyncSession], config: OidcConfig
    ) -> None:
        self._session_factory = session_factory
        self._config = config

    async def link(self, claims: IdentityClaims) -> User | None:
        async with ControlPlaneSession(self._session_factory()) as session:
            linked = await self._linked_user(session, claims)
            if linked is not None:
                return linked
            try:
                user = await self._trusted_email_user(session, claims)
                if user is None:
                    user = User(
                        id=uuid7(),
                        email=claims.email if claims.email_verified else None,
                        status="active",
                    )
                    session.add(user)
                    await session.flush()
                session.add(
                    IdentityLink(user_id=user.id, issuer=claims.issuer, subject=claims.subject)
                )
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return await self._linked_user(session, claims)
            return user

    async def _trusted_email_user(
        self, session: ControlPlaneSession, claims: IdentityClaims
    ) -> User | None:
        if not self._config.email_trusted or not claims.email_verified or not claims.email:
            return None
        return (
            await session.execute(
                sa.select(User).where(
                    sa.func.lower(User.email) == claims.email.lower(),
                    User.status == "active",
                )
            )
        ).scalar_one_or_none()

    async def _linked_user(
        self, session: ControlPlaneSession, claims: IdentityClaims
    ) -> User | None:
        link: IdentityLink | None = (
            await session.execute(
                sa.select(IdentityLink).where(
                    IdentityLink.issuer == claims.issuer,
                    IdentityLink.subject == claims.subject,
                )
            )
        ).scalar_one_or_none()
        if link is None:
            return None
        user: User | None = await session.get(User, link.user_id)
        if user is None or user.status != "active":
            return None
        link.last_login_at = datetime.now(UTC)
        await session.commit()
        return user


def _kid(token: str) -> str:
    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError as exc:
        raise InvalidToken("malformed token header") from exc
    kid = header.get("kid")
    if not isinstance(kid, str):
        raise InvalidToken("token has no kid")
    return kid


class OidcAuthenticator:
    def __init__(
        self,
        *,
        config: OidcConfig,
        cache: JwksCache,
        verifier: TokenVerifier,
        mapper: ClaimMapper,
        linker: UserLinker,
        audit: PlatformAudit,
    ) -> None:
        self._cache = cache
        self._verifier = verifier
        self._mapper = mapper
        self._linker = linker
        self._audit = audit

    async def authenticate(self, request: RequestInfo) -> Principal | None:
        token = bearer_token(request)
        if token is None:
            return None
        try:
            kid = _kid(token)
        except AuthenticationError:
            return None
        try:
            key = await self._cache.signing_key(kid)
            if key is None:
                raise InvalidToken("unknown signing key")
            claims = self._verifier.verify(token, key)
            identity = self._mapper.map(claims)
            user = await self._linker.link(identity)
        except Exception as exc:
            await record_authn_failure(self._audit, type(exc).__name__)
            return None
        if user is None:
            await record_authn_failure(self._audit, "unlinked_identity")
            return None
        return Principal(kind=PrincipalKind.USER, id=user.id, user_id=user.id)
