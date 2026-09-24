"""Gateway identity configuration (directive §18, spec #12).

A gateway is only trusted when the channel is authenticated, so the
configuration refuses combinations that would create false confidence:

* ``NONE`` may not carry a secret (there is no gateway to verify),
* ``SHARED_SECRET``/``HMAC`` require a secret of at least 32 bytes,
* unknown fields are rejected, so a deployment cannot add a "trust headers"
  switch, and header names are normalised to lowercase (ASGI convention).
"""

from __future__ import annotations

from datetime import timedelta
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, SecretStr, field_validator, model_validator

from jdlib.security.errors import SecurityConfigurationError

MIN_SECRET_BYTES = 32
_HMAC_MODES = ("shared_secret", "hmac")


class GatewayMode(StrEnum):
    """How (and whether) gateway identity assertions are verified."""

    NONE = "none"
    SHARED_SECRET = "shared_secret"
    HMAC = "hmac"


class GatewayConfig(BaseModel):
    """Trusted-gateway configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: GatewayMode = GatewayMode.NONE
    secret: SecretStr | None = None
    subject_header: str = "x-jdlib-subject"
    tenant_header: str = "x-jdlib-tenant"
    scopes_header: str = "x-jdlib-scopes"
    issued_at_header: str = "x-jdlib-issued-at"
    expires_at_header: str = "x-jdlib-expires-at"
    secret_header: str = "x-jdlib-gateway-secret"
    signature_header: str = "x-jdlib-signature"
    max_skew: timedelta = timedelta(seconds=60)

    @field_validator(
        "subject_header",
        "tenant_header",
        "scopes_header",
        "issued_at_header",
        "expires_at_header",
        "secret_header",
        "signature_header",
    )
    @classmethod
    def _lowercase(cls, value: str) -> str:
        if not value:
            raise SecurityConfigurationError("gateway header names must not be empty")
        return value.lower()

    @model_validator(mode="after")
    def _validate(self) -> GatewayConfig:
        if self.mode is GatewayMode.NONE:
            if self.secret is not None:
                raise SecurityConfigurationError(
                    "gateway mode 'none' must not carry a secret: there is no gateway to verify"
                )
        else:
            if self.secret is None:
                raise SecurityConfigurationError(
                    f"gateway mode '{self.mode.value}' requires a shared secret"
                )
            if len(self.secret.get_secret_value().encode()) < MIN_SECRET_BYTES:
                raise SecurityConfigurationError(
                    f"gateway secret must be at least {MIN_SECRET_BYTES} bytes"
                )
        if self.max_skew <= timedelta(0):
            raise SecurityConfigurationError("gateway max_skew must be positive")
        return self

    @property
    def secret_value(self) -> str | None:
        """The secret itself, for verification only (never logged or stored)."""
        return self.secret.get_secret_value() if self.secret is not None else None


__all__ = ["MIN_SECRET_BYTES", "GatewayConfig", "GatewayMode"]
