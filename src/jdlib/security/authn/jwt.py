"""JWT validation with explicit claim mapping (spec #7, #10, #56).

The validator is a thin, opinionated layer over the existing verifier:

* signature, issuer, audience and time claims are checked by
  :class:`jdlib.authn.oidc.TokenVerifier` (the same code the application
  authenticator uses — one implementation, not two),
* the algorithm list is allow-listed at construction time and never taken from
  the token,
* claim mapping is explicit: only the configured scope claims can produce
  authorization scopes, so ``roles``/``groups``/``permissions``-style claims
  cannot silently become privileges (spec #10),
* the result carries metadata only — never the raw token (spec #8).

Readiness follows spec #51: ``ready()`` asks the key source whether key
material is loaded, so health checks can distinguish "cannot validate tokens"
from "no tokens yet".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

import jwt as pyjwt

from jdlib.authn.oidc import TokenVerifier
from jdlib.config import OidcConfig
from jdlib.context import Clock, SystemClock
from jdlib.errors import AuthenticationError, InvalidToken
from jdlib.security.authn.algorithms import assert_safe_algorithms
from jdlib.security.context import TokenMetadata
from jdlib.security.interfaces import ValidatedToken


class SigningKeySource(Protocol):
    """Supplies public signing keys by ``kid`` (e.g. a JWKS cache)."""

    async def signing_key(self, kid: str) -> object | None: ...

    async def ready(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class JwtClaimMapping:
    """Explicit, validated mapping of token claims onto the security model."""

    issuer: str
    audience: str
    algorithms: tuple[str, ...] = ("RS256",)
    subject_claim: str = "sub"
    scope_claims: tuple[str, ...] = ("scope", "scp")
    client_id_claims: tuple[str, ...] = ("client_id", "azp")

    def __post_init__(self) -> None:
        assert_safe_algorithms(self.algorithms)


def _scopes_from_claims(
    claims: dict[str, object], claim_names: tuple[str, ...]
) -> frozenset[str]:
    """Collect scopes from the configured claims only.

    Anything else in the token (`roles`, `groups`, `permissions`, ...) is
    deliberately ignored: privileges must never be derived from arbitrary
    claims.
    """
    scopes: set[str] = set()
    for name in claim_names:
        value = claims.get(name)
        if isinstance(value, str):
            scopes.update(part for part in value.split() if part)
        elif isinstance(value, (list, tuple)):
            scopes.update(item for item in value if isinstance(item, str) and item)
    return frozenset(scopes)


class JwtTokenValidator:
    """Validates inbound JWT bearer tokens and returns metadata-only results."""

    def __init__(
        self,
        *,
        mapping: JwtClaimMapping,
        keys: SigningKeySource,
        clock: Clock | None = None,
        leeway: timedelta = timedelta(seconds=60),
    ) -> None:
        self._mapping = mapping
        self._keys = keys
        self._clock = clock or SystemClock()
        self._leeway = leeway
        # Reuse the production verifier: signature, issuer, audience and time
        # claims are validated in exactly one place.
        self._verifier = TokenVerifier(
            OidcConfig(
                issuer=mapping.issuer,
                audience=mapping.audience,
                algorithms=list(mapping.algorithms),
                leeway=leeway,
            ),
            clock=self._clock,
        )

    # -- TokenValidator port ------------------------------------------------

    @property
    def keys(self) -> SigningKeySource:
        """The key source backing this validator (diagnostics, health wiring)."""
        return self._keys

    async def validate(self, token: str) -> ValidatedToken:
        """Validate ``token``, raising a typed authentication error on failure."""
        kid = self._kid(token)
        try:
            key = await self._keys.signing_key(kid)
        except AuthenticationError:
            raise
        except Exception as exc:  # noqa: BLE001 - key lookup failures fail closed
            raise InvalidToken("signing key unavailable") from exc
        if key is None:
            raise InvalidToken("unknown signing key")
        claims = dict(self._verifier.verify(token, key))
        subject = claims.get(self._mapping.subject_claim)
        if not isinstance(subject, str) or not subject:
            raise InvalidToken("token has no subject claim")
        scopes = _scopes_from_claims(claims, self._mapping.scope_claims)
        return ValidatedToken(
            subject=subject,
            metadata=self._metadata(token, claims, subject, scopes),
            scopes=scopes,
        )

    async def ready(self) -> bool:
        """Report whether key material is loaded (spec #51)."""
        return await self._keys.ready()

    # -- Internals ----------------------------------------------------------

    def _metadata(
        self,
        token: str,
        claims: dict[str, object],
        subject: str,
        scopes: frozenset[str],
    ) -> TokenMetadata:
        return TokenMetadata(
            issuer=str(claims.get("iss", self._mapping.issuer)),
            audience=str(claims.get("aud", self._mapping.audience)),
            subject=subject,
            token_type=self._token_type(token),
            jti=str(claims["jti"]) if isinstance(claims.get("jti"), str) else None,
            expires_at=self._expires_at(claims),
            scopes=scopes,
            client_id=self._client_id(claims),
        )

    def _client_id(self, claims: dict[str, object]) -> str | None:
        for name in self._mapping.client_id_claims:
            value = claims.get(name)
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _expires_at(claims: dict[str, object]) -> datetime | None:
        value = claims.get("exp")
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), UTC)
        return None

    @staticmethod
    def _token_type(token: str) -> str | None:
        try:
            header = pyjwt.get_unverified_header(token)
        except pyjwt.PyJWTError:
            return None
        typ = header.get("typ")
        return typ if isinstance(typ, str) else None

    @staticmethod
    def _kid(token: str) -> str:
        try:
            header = pyjwt.get_unverified_header(token)
        except pyjwt.PyJWTError as exc:
            raise InvalidToken("malformed token header") from exc
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidToken("token has no kid")
        return kid


__all__ = ["JwtClaimMapping", "JwtTokenValidator", "SigningKeySource"]
