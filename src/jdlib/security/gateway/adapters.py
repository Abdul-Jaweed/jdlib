"""Gateway adapters (directive §18, §19; spec #12).

Identity asserted by an edge gateway is trusted only when the channel is
authenticated:

* :class:`NoGatewayAdapter` — no gateway: header assertions are ignored, so a
  direct caller cannot impersonate a user or a tenant by adding headers,
* :class:`KongGatewayAdapter` / :class:`TykGatewayAdapter` — verify the
  shared-secret or HMAC assertion the gateway injects before trusting any
  identity field, using each product's header conventions by default.

Verification is deliberately strict: a missing, empty and wrong secret are the
same outcome (no identity), the assertion must be complete, its validity window
must sit inside ``max_skew`` of now and must not span more than twice
``max_skew`` (replay bound), and the two modes cannot substitute for one
another — a signature never satisfies a shared-secret configuration and a bare
secret never satisfies a signing one.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime

from jdlib.context import Clock, SystemClock
from jdlib.security.gateway.config import GatewayConfig, GatewayMode
from jdlib.security.interfaces import GatewayIdentity
from jdlib.tenancy.resolution import RequestInfo


def _canonical(subject: str, tenant: str, scopes: str, issued: str, expires: str) -> str:
    """The exact byte string a signature covers (stable across products)."""
    normalized_scopes = ",".join(sorted(scopes.replace(",", " ").split()))
    return "\n".join([subject, tenant, normalized_scopes, issued, expires])


class _VerifiedGatewayAdapter:
    """Shared verification core; product adapters supply header defaults."""

    name = "gateway"

    def __init__(self, *, config: GatewayConfig, clock: Clock | None = None) -> None:
        self._config = self._with_product_defaults(config)
        self._clock = clock or SystemClock()

    @classmethod
    def _with_product_defaults(cls, config: GatewayConfig) -> GatewayConfig:
        defaults = getattr(cls, "_PRODUCT_HEADERS", {})
        if not defaults:
            return config
        updates = {
            field: value
            for field, value in defaults.items()
            if getattr(config, field) == GatewayConfig.model_fields[field].default
        }
        return config.model_copy(update=updates) if updates else config

    def __repr__(self) -> str:
        return f"{type(self).__name__}(mode={self._config.mode.value!r})"

    # -- configuration view ------------------------------------------------

    @property
    def config(self) -> GatewayConfig:
        return self._config

    @property
    def subject_header(self) -> str:
        return self._config.subject_header

    @property
    def tenant_header(self) -> str:
        return self._config.tenant_header

    @property
    def scopes_header(self) -> str:
        return self._config.scopes_header

    async def verify_identity(self, request: RequestInfo) -> GatewayIdentity | None:
        """Return the asserted identity, or ``None`` when it cannot be trusted."""
        headers = {key.lower(): value for key, value in request.headers.items()}
        if not self._channel_is_authentic(headers):
            return None
        identity = self._parse(headers)
        if identity is None:
            return None
        if not self._window_is_usable(identity):
            return None
        return identity

    # -- verification steps -------------------------------------------------

    def _channel_is_authentic(self, headers: dict[str, str]) -> bool:
        config = self._config
        secret = config.secret_value
        if secret is None:
            return False
        if config.mode is GatewayMode.SHARED_SECRET:
            provided = headers.get(config.secret_header) or ""
            return bool(provided) and hmac.compare_digest(provided, secret)
        signature = headers.get(config.signature_header)
        if not signature:
            return False
        expected = hmac.new(
            secret.encode(),
            _canonical(
                headers.get(config.subject_header, ""),
                headers.get(config.tenant_header, ""),
                headers.get(config.scopes_header, ""),
                headers.get(config.issued_at_header, ""),
                headers.get(config.expires_at_header, ""),
            ).encode(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(signature.lower(), expected)

    def _parse(self, headers: dict[str, str]) -> GatewayIdentity | None:
        config = self._config
        subject = headers.get(config.subject_header)
        if not subject:
            return None
        issued = self._timestamp(headers.get(config.issued_at_header))
        expires = self._timestamp(headers.get(config.expires_at_header))
        if issued is None or expires is None:
            return None
        raw_scopes = headers.get(config.scopes_header, "")
        scopes = frozenset(raw_scopes.replace(",", " ").split())
        return GatewayIdentity(
            subject=subject,
            tenant_slug=headers.get(config.tenant_header) or None,
            scopes=scopes,
            issued_at=issued,
            expires_at=expires,
        )

    @staticmethod
    def _timestamp(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (TypeError, ValueError, OverflowError, OSError):
            return None

    def _window_is_usable(self, identity: GatewayIdentity) -> bool:
        now = self._clock.now()
        if not identity.is_valid_at(now):
            return False
        span = identity.expires_at - identity.issued_at
        return span <= 2 * self._config.max_skew


class NoGatewayAdapter:
    """No gateway: identity may never come from request headers."""

    name = "none"

    def __init__(self) -> None:
        pass

    def __repr__(self) -> str:
        return "NoGatewayAdapter(mode='none')"

    async def verify_identity(self, request: RequestInfo) -> None:
        """Always ``None``: header assertions are ignored, not merely unverified."""
        return None


class KongGatewayAdapter(_VerifiedGatewayAdapter):
    """Kong (``kong:3.x``) by default injects ``x-jdlib-*`` headers.

    The deployment configures Kong's ``request-transformer`` (or a
    ``pre-function``) to set the identity headers and the gateway secret; Kong's
    own ``X-Consumer-*`` headers can be used instead by overriding
    ``subject_header``/``tenant_header``.
    """

    name = "kong"


class TykGatewayAdapter(_VerifiedGatewayAdapter):
    """Tyk uses its own namespaced headers by default.

    A deployment that sets the headers explicitly keeps its choice: the product
    defaults apply only where the configuration left the stock header name.
    """

    name = "tyk"
    _PRODUCT_HEADERS = {
        "subject_header": "x-tyk-jdlib-subject",
        "tenant_header": "x-tyk-jdlib-tenant",
        "scopes_header": "x-tyk-jdlib-scopes",
        "issued_at_header": "x-tyk-jdlib-issued-at",
        "expires_at_header": "x-tyk-jdlib-expires-at",
        "secret_header": "x-tyk-jdlib-gateway-secret",
        "signature_header": "x-tyk-jdlib-signature",
    }


__all__ = [
    "KongGatewayAdapter",
    "NoGatewayAdapter",
    "TykGatewayAdapter",
]
