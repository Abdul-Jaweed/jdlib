"""Ports for authentication, gateway and rate-limiting adapters (spec #5, #7,
#11, #35).

The core defines these protocols; integrations provide adapters (ZITADEL,
Cerbos, Kong, Tyk, Redis, ...). Nothing in this module imports an optional
dependency, so ``import jdlib.security.interfaces`` stays lightweight
(spec #74).

Security-relevant conventions shared by every adapter:

* inbound authentication (:class:`TokenValidator`) and outbound service
  authentication (:class:`TokenProvider`) are separate responsibilities and
  never share a type,
* raw credentials never appear in protocol results — validated tokens expose
  :class:`~jdlib.security.context.TokenMetadata`, outbound credentials are
  wrapped in :class:`pydantic.SecretStr`,
* denials are explicit: :class:`RateLimitDecision` defaults to *denied*, so an
  adapter that forgets to populate a decision fails closed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from pydantic import SecretStr

from jdlib.security.context import TokenMetadata
from jdlib.tenancy.resolution import RequestInfo


@dataclass(frozen=True, slots=True)
class ValidatedToken:
    """Result of validating an inbound credential.

    Deliberately carries no raw token: downstream code (logs, audit events,
    spans) cannot leak what it never received.
    """

    subject: str
    metadata: TokenMetadata
    scopes: frozenset[str] = frozenset()


@runtime_checkable
class TokenValidator(Protocol):
    """Inbound token validation (JWT/JWKS/OIDC, introspection, ...)."""

    async def validate(self, token: str) -> ValidatedToken:
        """Validate a bearer token, raising on any failure (fail closed)."""
        ...

    async def ready(self) -> bool:
        """Report whether key material is loaded and fresh (spec #51)."""
        ...


@dataclass(frozen=True, slots=True)
class OutboundToken:
    """A service credential for calling another system.

    ``value`` is a :class:`~pydantic.SecretStr`, so accidental ``repr()``,
    ``str()`` or log formatting masks it; the raw value must be requested
    explicitly by the HTTP adapter that attaches it to a request.
    """

    value: SecretStr
    expires_at: datetime
    token_type: str = "Bearer"


@runtime_checkable
class TokenProvider(Protocol):
    """Outbound service authentication (client credentials, private_key_jwt)."""

    async def token(
        self, *, audience: str, scopes: Sequence[str] = ()
    ) -> OutboundToken:
        """Return a cached-or-fresh service credential."""
        ...

    async def invalidate(self) -> None:
        """Drop cached credentials (rotation, revocation, forced refresh)."""
        ...


@dataclass(frozen=True, slots=True)
class GatewayIdentity:
    """Identity asserted by a trusted API gateway, bound to a validity window."""

    subject: str
    tenant_slug: str | None
    scopes: frozenset[str]
    issued_at: datetime
    expires_at: datetime

    def is_valid_at(self, now: datetime) -> bool:
        """Return whether ``now`` falls inside the asserted validity window."""
        return self.issued_at <= now <= self.expires_at


@runtime_checkable
class GatewayAdapter(Protocol):
    """Edge/gateway integration: identity propagation and edge metadata."""

    name: str

    async def verify_identity(self, request: RequestInfo) -> GatewayIdentity | None:
        """Return the gateway-asserted identity, or ``None`` when absent.

        Implementations must authenticate the channel (mTLS, signed envelope)
        and must not return an identity for unsigned or invalid assertions
        (spec #12).
        """
        ...


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Outcome of a rate-limit check; defaults to denied (fail closed)."""

    allowed: bool = False
    limit: int | None = None
    remaining: int | None = None
    retry_after: timedelta | None = None

    @classmethod
    def allow(cls, *, remaining: int | None = None, limit: int | None = None) -> RateLimitDecision:
        return cls(allowed=True, remaining=remaining, limit=limit)

    @classmethod
    def deny(
        cls, *, retry_after: timedelta | None = None, limit: int | None = None
    ) -> RateLimitDecision:
        return cls(allowed=False, retry_after=retry_after, limit=limit)


@runtime_checkable
class RateLimiter(Protocol):
    """Rate limiting is delegated to an adapter (gateway, Redis, custom)."""

    async def check(self, *, scope: str, identity: str) -> RateLimitDecision:
        """Consume one unit for ``identity`` in ``scope``."""
        ...


__all__ = [
    "GatewayAdapter",
    "GatewayIdentity",
    "OutboundToken",
    "RateLimitDecision",
    "RateLimiter",
    "TokenProvider",
    "TokenValidator",
    "ValidatedToken",
]
